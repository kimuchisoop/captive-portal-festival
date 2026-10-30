"""Event-day check records and allowlisted, locally downloadable support reports."""
import hashlib
import json
from datetime import datetime,timedelta,timezone
import uuid
from flask import g,jsonify,make_response,request
from database import DatabaseError
from jobs import secure_new_file
from worker_status import worker_status

CHECKS={
    'before': [('database','MySQLへの保存と接続'),('worker','定期処理の最終成功'),('backup','バックアップと直近の検証結果'),
               ('ssid','提供エリアのSSIDと電波'),('internet','来場者端末でのインターネット接続'),('portal','来場者向けの案内表示'),('contacts','当日の担当者と連絡先の共有')],
    'during': [('notifications','未対応通知と引き継ぎ'),('capacity','保存容量とバックアップ'),('crowding','提供エリアの混雑と案内'),('connectivity','来場者端末での接続状況')],
    'after': [('notice','提供終了の案内'),('network_end','実機での通信許可の終了確認'),('final_backup','最終バックアップと検証'),('records','ログ・記録・引き継ぎの保管')]
}

def event_day(s):
    return datetime.fromtimestamp(s.now(),timezone(timedelta(hours=9))).date().isoformat()

def parse_day(value):
    if not isinstance(value,str) or len(value)!=10: raise ValueError('Invalid day')
    parsed=datetime.strptime(value,'%Y-%m-%d').date()
    if parsed.isoformat()!=value: raise ValueError('Invalid day')
    return value

def support_payload(s,correlation_id):
    from app import utc
    from operations import mysql_diagnostic
    diagnostic=mysql_diagnostic(s.db_settings)
    # Build from allowed fields only. No raw logs, paths, notes, account names, addresses or settings dumps.
    allowed_codes={'connection','tls_transport','tls_identity','privileges','inspection'}
    checks=[{'code':c['code'],'status':c['status']} for c in diagnostic['checks'] if c['code'] in allowed_codes]
    with s.db() as db:
        counts={name:db.execute('SELECT count(*) FROM '+name).fetchone()[0] for name in ('consents','grants','operations')}
        jobs=db.execute("SELECT value FROM meta WHERE name='last_job_at'").fetchone()
        backup=db.execute("SELECT value FROM meta WHERE name='last_backup_at'").fetchone()
        alerts=db.execute("SELECT code,severity,state FROM notifications WHERE state!='resolved' ORDER BY code").fetchall()
    worker=worker_status(jobs[0] if jobs else None,s.now())
    backup_age=max(0,s.now()-int(backup[0])) if backup else None
    known_codes={'backup_legacy_size','retention_paused','adapter_unavailable','retention_unconfigured','disk_low','database_size_high',
                 'plan_review_pending','plan_review_required','plan_apply_unknown','plan_activation_pending','archive_export_failed','schema5_recovery_required','backup_size_high','backup_inventory_incomplete','capacity_thresholds_unconfigured','operation_failed','backup_overdue','database_structure','backup_failed'}
    return dict(format='festival-wifi-support-summary',format_version=1,release='0.11.10-rc1',checked_at_utc=utc(s.now()),
                correlation_id=correlation_id,database_schema=5,mode='local',production_enabled=False,ap_adapter='disconnected',
                automatic_deletion_enabled=False,counts=counts,
                worker=dict(age_seconds=worker['age_seconds'],stale=worker['stale']),backup=dict(age_seconds=backup_age),
                mysql=dict(connected=diagnostic['connected'],checks=checks),
                notifications=[dict(code=r['code'] if r['code'] in known_codes else 'other_notification',
                                    severity=r['severity'] if r['severity'] in ('warning','critical') else 'unknown',
                                    state=r['state'] if r['state'] in ('open','acknowledged') else 'unknown') for r in alerts],
                omissions=['raw_logs','account_names','addresses','record_bodies','free_text','database_target','passwords','keys','cookies','device_identifiers'])

def register_readiness(app,s,auth,body):
    from app import ApiError,uid,utc
    from backup_review import backup_path,decrypt_check

    @app.post('/v1/admin/backups/<filename>/checks')
    @auth('admin','records')
    def backup_verify(filename):
        body(())
        try:
            from backup_review import WEB_VERIFY_BYTES
            path=backup_path(s,filename)
            if path.exists() and path.stat().st_size>WEB_VERIFY_BYTES:
                raise ApiError('verify_at_terminal',409,'64MiBを超える検証は、運営中の処理を長く待たせないようサーバー端末のverify-backupで実行してください。')
        except ValueError: raise ApiError('backup_name_invalid')
        with s.db(True) as db:
            def action():
                result=decrypt_check(s,filename,g.session['owner_id'],db=db)
                return result,201,s.now()+86400
            return s.idempotent(db,g.session['owner_id'],action)

    @app.get('/v1/admin/backups/<filename>/checks')
    @auth('admin','records')
    def backup_history(filename):
        try: backup_path(s,filename)
        except ValueError: raise ApiError('backup_name_invalid')
        try:
            if set(request.args)-{'before'}: raise ValueError()
            before=int(request.args.get('before','9223372036854775807'))
            if before<=0: raise ValueError()
        except ValueError: raise ApiError('cursor_invalid')
        with s.db() as db:
            rows=db.execute('SELECT id,stage,status,code,ciphertext_sha256,checked_at,seq FROM backup_checks WHERE filename=? AND seq<? ORDER BY seq DESC LIMIT 101',(filename,before)).fetchall()
        return jsonify(items=[dict(id=r['id'],stage=r['stage'],status=r['status'],code=r['code'],ciphertext_sha256=r['ciphertext_sha256'],checked_at_utc=utc(r['checked_at'])) for r in rows[:100]],
                       next_cursor=rows[99]['seq'] if len(rows)>100 else None)

    @app.post('/v1/admin/support-bundles')
    @auth('admin','operate')
    def support_create():
        d=body(('correlation_id',));correlation=d['correlation_id']
        try:
            if correlation is not None:
                if not isinstance(correlation,str): raise ValueError()
                uuid.UUID(correlation)
        except (ValueError,AttributeError): raise ApiError('correlation_invalid',400,'調査番号の形式を確認するか、空欄で作成してください。')
        # No external send: only an authenticated local file is created for the operator to download.
        payload=support_payload(s,correlation)
        with s.db(True) as db:
            def action():
                report_id=uid();directory=s.home/'support-reports'
                if directory.is_symlink(): raise ApiError('report_storage_invalid',503)
                directory.mkdir(mode=0o700,exist_ok=True)
                from security import protect_directory
                protect_directory(directory)
                data=json.dumps(dict(report_id=report_id,**payload),ensure_ascii=False,indent=2).encode()
                secure_new_file(directory/(report_id+'.json'),data)
                db.execute('INSERT INTO support_exports (id,actor,created_at,sha256,bytes) VALUES (?,?,?,?,?)',
                           (report_id,g.session['owner_id'],s.now(),hashlib.sha256(data).hexdigest(),len(data)))
                s.audit(db,g.session['owner_id'],'support_bundle_created',report_id)
                return dict(report_id=report_id,download_url='/v1/admin/support-bundles/'+report_id,external_send=False),201,s.now()+86400
            return s.idempotent(db,g.session['owner_id'],action)

    @app.get('/v1/admin/support-bundles')
    @auth('admin','operate')
    def support_list():
        with s.db() as db: rows=db.execute('SELECT id,created_at,bytes FROM support_exports ORDER BY seq DESC LIMIT 20').fetchall()
        return jsonify(items=[dict(report_id=r['id'],created_at_utc=utc(r['created_at']),bytes=r['bytes'],download_url='/v1/admin/support-bundles/'+r['id']) for r in rows])

    @app.get('/v1/admin/support-bundles/<report_id>')
    @auth('admin','operate')
    def support_download(report_id):
        try: uuid.UUID(report_id)
        except ValueError: raise ApiError('report_not_found',404)
        with s.db() as db: row=db.execute('SELECT * FROM support_exports WHERE id=?',(report_id,)).fetchone()
        if not row: raise ApiError('report_not_found',404)
        directory=s.home/'support-reports';path=directory/(report_id+'.json')
        if directory.is_symlink() or path.is_symlink(): raise ApiError('report_unavailable',503)
        try:
            with path.open('rb') as handle: data=handle.read(1048577)
        except OSError: raise ApiError('report_unavailable',503,'資料のファイルがありません。新しく作成してください。')
        if len(data)>1048576 or hashlib.sha256(data).hexdigest()!=row['sha256']: raise ApiError('report_integrity_failed',503)
        with s.db(True) as db: s.audit(db,g.session['owner_id'],'support_bundle_downloaded',report_id)
        response=make_response(data);response.headers['Content-Type']='application/json; charset=utf-8'
        response.headers['Content-Disposition']='attachment; filename="support-'+report_id+'.json"'
        return response

    @app.get('/v1/admin/checklists')
    @auth('admin','read')
    def checklist_get():
        try:
            if set(request.args)-{'day','phase','before'}: raise ValueError()
            day=parse_day(request.args.get('day',event_day(s)));phase=request.args.get('phase','before')
            if phase not in CHECKS: raise ValueError()
            before=int(request.args.get('before','9223372036854775807'))
            if before<=0: raise ValueError()
        except (ValueError,TypeError): raise ApiError('checklist_query_invalid')
        with s.db() as db:
            run=db.execute('SELECT * FROM checklist_runs WHERE event_day=? AND phase=?',(day,phase)).fetchone()
            people=db.execute("SELECT id,username FROM admins WHERE enabled=1 AND role IN ('operator','settings') ORDER BY username").fetchall()
            items=[];pending=problems=confirmed=0
            for item_id,label in CHECKS[phase]:
                entry=db.execute('SELECT e.*,a.username AS actor_name,b.username AS assignee_name FROM checklist_entries e '
                                 'JOIN admins a ON a.id=e.actor LEFT JOIN admins b ON b.id=e.assignee WHERE run_id=? AND item_id=? ORDER BY seq DESC LIMIT 1',
                                 (run['id'],item_id)).fetchone() if run else None
                outcome=entry['outcome'] if entry else 'pending'
                pending+=outcome=='pending';problems+=outcome=='problem';confirmed+=outcome in ('ok','na')
                items.append(dict(item_id=item_id,label=label,entry=dict(entry) if entry else None))
            history=db.execute('SELECT e.*,a.username AS actor_name FROM checklist_entries e JOIN admins a ON a.id=e.actor '
                               'WHERE run_id=? AND e.seq<? ORDER BY e.seq DESC LIMIT 101',(run['id'],before)).fetchall() if run else []
        return jsonify(day=day,today_jst=event_day(s),phase=phase,checklist_version=1,run=dict(run) if run else None,items=items,
                       assignees=[dict(p) for p in people],summary=dict(pending=pending,problems=problems,confirmed=confirmed,total=len(items)),
                       history=[dict(r) for r in history[:100]],next_cursor=history[99]['seq'] if len(history)>100 else None,
                       network_verification=False)

    @app.post('/v1/admin/checklists')
    @auth('admin','operate')
    def checklist_create():
        d=body(('day','phase'))
        try:
            parse_day(d['day'])
            if d['phase'] not in CHECKS: raise ValueError()
        except (ValueError,TypeError): raise ApiError('checklist_query_invalid')
        with s.db(True) as db:
            def action():
                run=db.execute('SELECT id FROM checklist_runs WHERE event_day=? AND phase=?',(d['day'],d['phase'])).fetchone()
                if run: return dict(run_id=run['id']),200,s.now()+86400
                run_id=uid()
                db.execute('INSERT INTO checklist_runs VALUES (?,?,?,?,?,?)',(run_id,d['day'],d['phase'],1,g.session['owner_id'],s.now()))
                s.audit(db,g.session['owner_id'],'checklist_created',run_id)
                return dict(run_id=run_id),201,s.now()+86400
            return s.idempotent(db,g.session['owner_id'],action)

    @app.post('/v1/admin/checklists/<run_id>/entries')
    @auth('admin','operate')
    def checklist_update(run_id):
        d=body(('item_id','outcome','assignee','note','expected_entry_id'))
        if (not isinstance(d['item_id'],str) or d['outcome'] not in ('pending','ok','problem','na')
            or not isinstance(d['note'],str) or len(d['note'])>1000
            or any(v is not None and not isinstance(v,str) for v in (d['assignee'],d['expected_entry_id']))
            or (d['outcome'] in ('problem','na') and not d['note'].strip())
            or (d['outcome']!='pending' and not d['assignee'])):
            raise ApiError('checklist_entry_invalid',400,'担当者・確認結果・理由を確認してください。要対応・対象外の場合は理由が必要です。')
        with s.db(True) as db:
            def action():
                run=db.execute('SELECT * FROM checklist_runs WHERE id=?',(run_id,)).fetchone()
                if not run: raise ApiError('checklist_not_found',404)
                if d['item_id'] not in dict(CHECKS[run['phase']]): raise ApiError('checklist_item_invalid')
                last=db.execute('SELECT id FROM checklist_entries WHERE run_id=? AND item_id=? ORDER BY seq DESC LIMIT 1',(run_id,d['item_id'])).fetchone()
                if (last['id'] if last else None)!=d['expected_entry_id']: raise ApiError('checklist_changed',409,'別の確認が記録されました。一覧を更新してください。')
                if d['assignee'] is not None and not db.execute("SELECT id FROM admins WHERE id=? AND enabled=1 AND role IN ('operator','settings')",(d['assignee'],)).fetchone(): raise ApiError('assignee_invalid')
                entry_id=uid()
                db.execute('INSERT INTO checklist_entries (id,run_id,item_id,actor,assignee,outcome,note,checked_at) VALUES (?,?,?,?,?,?,?,?)',
                           (entry_id,run_id,d['item_id'],g.session['owner_id'],d['assignee'],d['outcome'],d['note'].strip(),s.now()))
                s.audit(db,g.session['owner_id'],'checklist_updated',run_id)
                return dict(entry_id=entry_id,network_verification=False),201,s.now()+86400
            return s.idempotent(db,g.session['owner_id'],action)
