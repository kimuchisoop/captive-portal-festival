"""Real HTTP smoke test with a disposable loopback server. No AP simulation."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.deps')]
import http.cookiejar
import json
import os
import secrets
import socket
import subprocess
from mysql_fixture import new_database, PreservedDirectory
import time
import urllib.error
import urllib.request
from app import Service, uid
from jobs import run_jobs
from manage import initialize, add_admin, mint_launch
from werkzeug.security import generate_password_hash


def main():
    checks = []
    with __import__('contextlib').nullcontext(PreservedDirectory().name) as temp:
        home = Path(temp) / 'http-data'
        initialize(home, sample=True, db_settings=new_database())
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        origin = 'http://127.0.0.1:' + str(port)
        config = json.loads((home / 'config.json').read_text(encoding='utf-8'))
        config['origin'] = origin
        (home / 'config.json').write_text(json.dumps(config), encoding='utf-8')
        s = Service(home)
        password = secrets.token_urlsafe(24)
        add_admin(s, 'httpqa', 'settings', generate_password_hash(password, method='scrypt'))
        cmd = [sys.executable, str(ROOT / 'manage.py'), '--home', str(home), 'serve']
        server_stdout=(home/'http-stdout.log').open('xb')
        server_stderr=(home/'http-stderr.log').open('xb')
        process = subprocess.Popen(cmd, stdout=server_stdout, stderr=server_stderr,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        def req(path, data=None, csrf=None, key=None, bad_origin=False):
            headers = {'Content-Type': 'application/json', 'Origin': 'https://invalid.example' if bad_origin else origin}
            if csrf: headers['X-CSRF-Token'] = csrf
            if key: headers['Idempotency-Key'] = key
            request = urllib.request.Request(origin + path, data=json.dumps(data).encode() if data is not None else None, headers=headers)
            try: r = opener.open(request, timeout=3)
            except urllib.error.HTTPError as e: r = e
            raw = r.read()
            return r.status, json.loads(raw) if r.headers.get_content_type() == 'application/json' else raw, r.headers
        def check(name, value):
            if not value: raise AssertionError(name)
            checks.append(name)
        try:
            for _ in range(100):
                if process.poll() is not None: raise RuntimeError('HTTP server exited')
                try:
                    if req('/health/live')[0] == 200: break
                except (OSError, urllib.error.URLError): time.sleep(.05)
            else: raise TimeoutError('HTTP server not ready')
            check('live', req('/health/live')[0] == 200)
            check('ready', req('/health/ready')[0] == 200)
            check('worker_stale', req('/health/jobs')[0] == 503)
            check('anonymous_admin_rejected', req('/v1/admin/overview')[0] == 401)
            check('cross_origin_rejected', req('/v1/session', {}, bad_origin=True)[0] == 403)
            _, bootstrap, _ = req('/v1/admin/session', {})
            status, admin, headers = req('/v1/admin/login', {'username':'httpqa', 'password':password}, bootstrap['csrf_token'])
            check('real_http_login', status == 200 and 'HttpOnly' in headers['Set-Cookie'])
            check('authenticated_overview', req('/v1/admin/overview')[0] == 200)
            _, session, _ = req('/v1/session', {})
            csrf = session['csrf_token']
            launch = mint_launch(s).split('=', 1)[1]
            status, context, _ = req('/v1/contexts', {'launch_ref':launch}, csrf, uid())
            check('verified_local_context', status == 201)
            _, context, _ = req('/v1/contexts/' + context['context_id'] + '?lang=en')
            t = context['terms']
            payload = dict(context_id=context['context_id'], accepted=True, terms_document_id=t['document_id'],
                           terms_sha256=t['sha256'], policy_version=t['policy_version'], language='en')
            key = uid(); status, one, _ = req('/v1/consents', payload, csrf, key)
            check('consent_saved', status == 201)
            status, two, _ = req('/v1/consents', payload, csrf, key)
            check('retry_same_ids', status == 201 and one == two)
            status, grant, _ = req('/v1/grants/' + one['grant_id'])
            check('no_false_connection', status == 200 and not grant['network_verified'] and grant['display_state'] != 'connected')
            check('handoff_blocked', req('/v1/grants/' + one['grant_id'] + '/handoffs', {}, csrf)[0] == 503)
            status, revoked, _ = req('/v1/admin/grants/' + one['grant_id'] + '/revocations', {'reason':'operator_request'}, admin['csrf_token'], uid())
            check('revocation_queued', status == 202 and not revoked['network_verified'])
            run_jobs(s)
            check('worker_heartbeat', req('/health/jobs')[0] == 200)
            _, operation, _ = req('/v1/admin/operations/' + revoked['operation_id'])
            check('disconnect_not_fabricated', operation['status'] == 'failed' and operation['last_error_code'] == 'adapter_unavailable')
            status, notifications, _ = req('/v1/admin/notifications')
            check('failure_notification', status == 200 and any(n['code'] == 'operation_failed' for n in notifications['items']))
            status, csv, _ = req('/v1/admin/consents/export')
            check('csv_real_http', status == 200 and one['consent_id'].encode() in csv)
            status, storage, _ = req('/v1/admin/storage')
            check('storage_estimate_and_unknown_db_disk',status==200 and storage['database_size_is_estimate'] and storage['database_disk_free_bytes'] is None)
            status, catalog, _ = req('/v1/admin/backups')
            check('backup_catalog_preserves_files',status==200 and catalog['total_files']>=1 and not catalog['automatic_deletion_enabled'])
            status, audit, _ = req('/v1/admin/audit?action=login')
            check('audit_search_real_http',status==200 and len(audit['items'])==1 and audit['items'][0]['actor_label']=='httpqa')
            check('diagnostic_csrf_required',req('/v1/admin/diagnostics',{},'invalid')[0]==403)
            status, diagnostic, _ = req('/v1/admin/diagnostics',{},admin['csrf_token'])
            check('diagnostic_without_permission_changes',status==200 and not diagnostic['mutation_performed'] and diagnostic['audit_saved'])
            status, audit, _ = req('/v1/admin/audit?action=diagnostic_run')
            check('diagnostic_audit_saved',status==200 and len(audit['items'])==1 and audit['items'][0]['object_id']==diagnostic['report_id'])
            status, ap, _ = req('/v1/admin/ap-readiness')
            check('ap_unknown_does_not_enable_networking',status==200 and len(ap['missing'])==6 and not ap['production_ready'] and not ap['live_verified'])
            filename=catalog['items'][0]['filename'];verification_path='/v1/admin/backups/'+filename+'/checks'
            check('backup_check_csrf_rejected',req(verification_path,{},'bad',uid())[0]==403)
            verification_key=uid();status,verification,_=req(verification_path,{},admin['csrf_token'],verification_key)
            check('backup_authenticated_on_disk',status==201 and verification['status']=='passed')
            check('backup_check_retry_same_record',req(verification_path,{},admin['csrf_token'],verification_key)[1]==verification)
            status,catalog_checked,_=req('/v1/admin/backups')
            item=next(b for b in catalog_checked['items'] if b['filename']==filename)
            check('backup_catalog_decrypt_separate_from_restore',item['checks']['decrypt']['status']=='passed' and item['checks']['restore'] is None)
            status,report,_=req('/v1/admin/support-bundles',{'correlation_id':None},admin['csrf_token'],uid())
            check('support_summary_saved_locally',status==201 and not report['external_send'])
            status,download,_=req(report['download_url'])
            check('support_download_no_secrets',status==200 and s.db_settings['password'] not in json.dumps(download) and s.db_settings['database'] not in json.dumps(download) and 'target' not in download['mysql'])
            status,daily,_=req('/v1/admin/checklists')
            check('daily_starts_unconfirmed',status==200 and daily['summary']['pending']==daily['summary']['total'])
            status,run,_=req('/v1/admin/checklists',{'day':daily['day'],'phase':'before'},admin['csrf_token'],uid())
            check('daily_run_created',status==201)
            data=dict(item_id=daily['items'][0]['item_id'],outcome='problem',assignee=daily['assignees'][0]['id'],note='HTTP review: operator follow-up required',expected_entry_id=None)
            path='/v1/admin/checklists/'+run['run_id']+'/entries';status,entry,_=req(path,data,admin['csrf_token'],uid())
            check('daily_problem_recorded',status==201 and not entry['network_verification'])
            check('daily_stale_update_rejected',req(path,data,admin['csrf_token'],uid())[0]==409)
            data.update(outcome='ok',note='HTTP review complete',expected_entry_id=entry['entry_id'])
            check('daily_confirmation_retains_history',req(path,data,admin['csrf_token'],uid())[0]==201 and len(req('/v1/admin/checklists')[1]['history'])==2)
            check('logout', req('/v1/admin/logout', {}, admin['csrf_token'])[0] == 200)
            check('logout_blocks_access', req('/v1/admin/overview')[0] == 401)
            _, bootstrap, _ = req('/v1/admin/session', {})
            _, admin, _ = req('/v1/admin/login', {'username':'httpqa','password':password},bootstrap['csrf_token'])
            admin_csrf=admin['csrf_token']
            status,cases,_=req('/v1/admin/notification-cases')
            check('notification_cases_real_http',status==200 and len(cases['items'])>0)
            case=cases['items'][0]
            handover=dict(generation=case['generation'],expected_update_id=None,assignee=cases['assignees'][0]['id'],status='in_progress',note='HTTP review: waiting for AP inventory')
            key=uid();path='/v1/admin/notification-cases/'+case['id']
            status,updated,_=req(path,handover,admin_csrf,key)
            check('handover_saved',status==201 and updated['condition_unchanged'])
            check('handover_retry_same_record',req(path,handover,admin_csrf,key)[1]==updated)
            check('handover_stale_rejected',req(path,handover,admin_csrf,uid())[0]==409)
            status,trend,_=req('/v1/admin/storage-history')
            check('growth_no_fabricated_forecast',status==200 and trend['forecast'] is None and len(trend['items'])>=1)
            draft=dict(version='http-review-2',policy_version='http-policy-2',ja='HTTP確認用の仮規約',en='HTTP review provisional terms')
            status,revision,_=req('/v1/admin/terms-revisions',draft,admin_csrf,uid())
            check('terms_draft_saved',status==201)
            _,preview,_=req('/v1/admin/terms-revisions/'+revision['revision_id'])
            check('terms_plain_preview',preview['ja']==draft['ja'] and len(preview['preview_sha256'])==64)
            publication=dict(revision_id=preview['id'],preview_sha256=preview['preview_sha256'],expected_publication_id=None)
            status,published,_=req('/v1/admin/terms-publications',publication,admin_csrf,uid())
            check('terms_applied_only_locally',status==201 and published['scope']=='local_only' and not published['production_enabled'])
            check('public_reads_published_terms',req('/v1/public')[1]['terms']['document_id']==preview['id'])
            check('settings_reads_current_version',req('/v1/admin/settings')[1]['terms_version']==draft['version'])
            req('/v1/admin/logout',{},admin_csrf)
            import base64
            from mfa import enroll,totp
            secret=base64.b32encode(secrets.token_bytes(20)).decode()
            codes=enroll(s,'httpqa',secret,totp(secret,s.now()//30))
            _,bootstrap,_=req('/v1/admin/session',{})
            status,pending,_=req('/v1/admin/login',{'username':'httpqa','password':password},bootstrap['csrf_token'])
            check('mfa_challenge_real_http',status==200 and pending['mfa_required'] and not pending['authenticated'])
            check('mfa_pending_no_admin_access',req('/v1/admin/overview')[0]==401)
            check('mfa_csrf_rejected',req('/v1/admin/mfa',{'code':codes[0]},'invalid')[0]==403)
            status,verified,_=req('/v1/admin/mfa',{'code':totp(secret,s.now()//30+1)},pending['csrf_token'])
            check('mfa_totp_real_http',status==200 and verified['authenticated'])
            check('mfa_status_has_no_secret',secret not in json.dumps(req('/v1/admin/mfa-status')[1]))
            req('/v1/admin/logout',{},verified['csrf_token'])
            _,bootstrap,_=req('/v1/admin/session',{})
            _,pending,_=req('/v1/admin/login',{'username':'httpqa','password':password},bootstrap['csrf_token'])
            status,verified,_=req('/v1/admin/mfa',{'code':codes[0]},pending['csrf_token'])
            check('mfa_recovery_real_http',status==200 and verified['authenticated'])
            check('mfa_recovery_consumed',req('/v1/admin/mfa-status')[1]['recovery_codes_remaining']==7)
            req('/v1/admin/logout',{},verified['csrf_token'])
        finally:
            process.terminate()
            process.wait(timeout=10)
            server_stdout.close();server_stderr.close()
    print(json.dumps({'passed':len(checks), 'failed':0, 'checks':checks}, ensure_ascii=False, indent=2))


if __name__ == '__main__': main()
