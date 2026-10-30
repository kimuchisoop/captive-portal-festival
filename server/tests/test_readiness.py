import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'.deps')]
import hashlib,json,shutil,unittest
from unittest.mock import patch
from cryptography.fernet import Fernet
from app import uid,timestamp,Service
from jobs import backup,V3_TABLES,notify
from database import DatabaseError,initialize_schema,transaction
from backup_review import backup_path,decrypt_check,restore_check
from deployment_plan import inspect_plan,render_closed_config,write_plan
from migrations import upgrade_to_v4
from mysql_fixture import new_database
import test_service as service_tests

class ReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): service_tests.Tests.setUpClass.__func__(cls)
    setUp=service_tests.Tests.setUp
    tearDown=service_tests.Tests.tearDown
    get=service_tests.Tests.get
    post=service_tests.Tests.post
    login=service_tests.Tests.login
    count=service_tests.Tests.count
    visitor=service_tests.Tests.visitor
    context=service_tests.Tests.context
    consent_data=service_tests.Tests.consent_data
    consent=service_tests.Tests.consent

    def test_new_endpoints_auth_and_roles(self):
        for path in ('/v1/admin/checklists','/v1/admin/support-bundles'):
            self.assertEqual(self.get(path).status_code,401)
        self.login('viewer')
        self.assertEqual(self.get('/v1/admin/checklists').status_code,200)
        self.assertEqual(self.post('/v1/admin/checklists',dict(day='2026-10-19',phase='before')).status_code,403)
        self.assertEqual(self.get('/v1/admin/support-bundles').status_code,403)
        self.assertEqual(self.post('/v1/admin/support-bundles',dict(correlation_id=None)).status_code,403)
        self.login('operator')
        path=backup(self.s)
        self.assertEqual(self.post('/v1/admin/backups/'+path.name+'/checks').status_code,403)
        self.login('records')
        self.assertEqual(self.post('/v1/admin/backups/'+path.name+'/checks').status_code,201)
        self.assertEqual(self.get('/v1/admin/support-bundles').status_code,403)

    def test_backup_decrypt_actual_result_and_idempotency(self):
        path=backup(self.s);self.login('records');key=uid()
        route='/v1/admin/backups/'+path.name+'/checks'
        a=self.post(route,key=key);b=self.post(route,key=key)
        self.assertEqual(a.status_code,201,a.json);self.assertEqual(a.json,b.json)
        self.assertEqual(a.json['status'],'passed');self.assertEqual(self.count('backup_checks'),1)
        catalog=self.get('/v1/admin/backups').json['items'][0]
        self.assertEqual(catalog['checks']['decrypt']['status'],'passed');self.assertIsNone(catalog['checks']['restore'])
        self.assertEqual(catalog['verification'],'decrypt_checked')
        history=self.get(route).json['items'];self.assertEqual(len(history),1)
        self.assertEqual(history[0]['ciphertext_sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(self.post(route,csrf='bad').status_code,403)

    def test_decrypt_wrong_key_or_tamper_is_failed_not_passed(self):
        path=backup(self.s);wrong=self.home/'wrong-review.key';wrong.write_bytes(Fernet.generate_key())
        result=decrypt_check(self.s,path.name,key_file=wrong)
        self.assertEqual(result['status'],'failed');self.assertEqual(result['code'],'authentication_failed')
        damaged=bytearray(path.read_bytes());damaged[-20]^=1
        second=path.parent/('backup-'+str(self.s.now())+'-'+uid()+'.fernet');second.write_bytes(damaged)
        self.assertEqual(decrypt_check(self.s,second.name)['status'],'failed')
        self.assertTrue(path.exists());self.assertEqual(self.count('backup_checks'),2)

    def test_verification_is_invalidated_by_file_change(self):
        path=backup(self.s);decrypt_check(self.s,path.name);self.login('records')
        with path.open('ab') as file: file.write(b'changed')
        item=self.get('/v1/admin/backups').json['items'][0]
        self.assertEqual(item['checks']['decrypt']['status'],'file_changed')
        self.assertEqual(item['verification'],'not_checked')

    def test_authenticated_but_malformed_snapshot_records_failure(self):
        directory=self.home/'backups';directory.mkdir(exist_ok=True)
        file=directory/('backup-'+str(self.s.now())+'-'+uid()+'.fernet')
        file.write_bytes(Fernet((self.home/'backup.key').read_bytes()).encrypt(b'[]'))
        self.login('records')
        result=self.post('/v1/admin/backups/'+file.name+'/checks')
        self.assertEqual(result.status_code,201,result.json)
        self.assertEqual(result.json['status'],'failed');self.assertEqual(result.json['code'],'snapshot_invalid')

    def test_backup_name_and_symlink_rejected(self):
        for name in ('../config.json','backup-1-notuuid.fernet','x/backup-1-'+uid()+'.fernet'):
            with self.assertRaises(ValueError): backup_path(self.s,name)
        self.login('records')
        self.assertEqual(self.post('/v1/admin/backups/not-a-backup/checks').status_code,400)
        with patch('backup_review.is_link',return_value=True):
            with self.assertRaises(ValueError): backup_path(self.s,'backup-1-'+uid()+'.fernet')

    def test_admin_changes_invalidate_pending_mfa_sessions(self):
        from manage import change_admin
        with self.s.db(True) as db:
            administrator=db.execute("SELECT id FROM admins WHERE username='settings'").fetchone()[0]
            self.s.new_session(db,'admin_mfa',administrator)
        change_admin(self.s,'settings',password_hash=self.password_hash)
        with self.s.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM sessions WHERE kind LIKE 'admin%' AND owner_id=?",(administrator,)).fetchone()[0],0)

    def test_backup_verification_history_is_immutable(self):
        path=backup(self.s);decrypt_check(self.s,path.name)
        with self.assertRaises(DatabaseError):
            with self.s.db(True) as db: db.execute("UPDATE backup_checks SET status='failed'")


    def test_restore_check_refuses_original_and_preserves_nonempty_target(self):
        path=backup(self.s)
        with self.assertRaises(ValueError): restore_check(self.s,path.name,self.home.parent/'same-source',self.s.db_settings)
        target=new_database()
        with transaction(target,True) as db:
            db.execute('CREATE TABLE keep_me (value BIGINT)');db.execute('INSERT INTO keep_me VALUES (42)')
        destination=self.home.parent/'nonempty-target'
        result=restore_check(self.s,path.name,destination,target)
        self.assertEqual(result['status'],'failed');self.assertFalse(destination.exists())
        with transaction(target) as db: self.assertEqual(db.execute('SELECT value FROM keep_me').fetchone()[0],42)



    def test_support_summary_omits_secrets_free_text_and_targets(self):
        secret_note='NEVER_INCLUDE_PRIVATE_NOTE_0abc'
        with self.s.db(True) as db: notify(db,self.s.now(),'adapter_unavailable',secret_note)
        self.s.config['never_export']=secret_note
        self.login('operator');key=uid()
        first=self.post('/v1/admin/support-bundles',dict(correlation_id=None),key=key)
        self.assertEqual(first.status_code,201,first.json)
        self.assertEqual(self.post('/v1/admin/support-bundles',dict(correlation_id=None),key=key).json,first.json)
        self.assertEqual(self.count('support_exports'),1)
        response=self.get(first.json['download_url']);self.assertEqual(response.status_code,200)
        text=response.get_data(as_text=True)
        for value in (secret_note,self.password,self.password_hash,self.s.db_settings['password'],self.s.db_settings['database'],'127.0.0.1'):
            self.assertNotIn(value,text)
        self.assertIn('attachment;',response.headers['Content-Disposition'])
        self.assertFalse(response.json['production_enabled']);self.assertFalse(first.json['external_send'])
        self.assertTrue((self.home/'support-reports'/(first.json['report_id']+'.json')).exists())

    def test_support_invalid_correlation_csrf_and_tamper(self):
        self.login('operator')
        self.assertEqual(self.post('/v1/admin/support-bundles',dict(correlation_id='do not export this')).status_code,400)
        self.assertEqual(self.post('/v1/admin/support-bundles',dict(correlation_id=None),csrf='bad').status_code,403)
        result=self.post('/v1/admin/support-bundles',dict(correlation_id=uid())).json
        path=self.home/'support-reports'/(result['report_id']+'.json')
        with path.open('ab') as file: file.write(b' ')
        self.assertEqual(self.get(result['download_url']).status_code,503)
        self.assertEqual(self.get('/v1/admin/support-bundles/not-a-uuid').status_code,404)

    def test_checklist_day_is_jst_and_all_items_start_pending(self):
        self.clock.value=timestamp('2026-10-18T15:01:00Z');self.login('viewer')
        r=self.get('/v1/admin/checklists').json
        self.assertEqual(r['day'],'2026-10-19');self.assertIsNone(r['run'])
        self.assertEqual(r['summary']['pending'],r['summary']['total']);self.assertEqual(r['summary']['confirmed'],0)
        self.assertFalse(r['network_verification'])

    def checklist(self):
        self.login('operator');day='2026-10-19'
        r=self.post('/v1/admin/checklists',dict(day=day,phase='before'))
        self.assertEqual(r.status_code,201,r.json)
        state=self.get('/v1/admin/checklists?day='+day+'&phase=before').json
        data=dict(item_id=state['items'][0]['item_id'],outcome='problem',assignee=state['assignees'][0]['id'],note='確認待ちのため運営へ引き継ぎ',expected_entry_id=None)
        return r.json['run_id'],data

    def test_checklist_create_retry_and_updates_preserve_history(self):
        run,data=self.checklist();path='/v1/admin/checklists/'+run+'/entries';key=uid()
        first=self.post(path,data,key=key);self.assertEqual(first.status_code,201,first.json)
        self.assertEqual(self.post(path,data,key=key).json,first.json)
        self.assertEqual(self.post(path,data).status_code,409)
        data.update(outcome='ok',note='確認完了',expected_entry_id=first.json['entry_id'])
        self.assertEqual(self.post(path,data).status_code,201)
        state=self.get('/v1/admin/checklists?day=2026-10-19&phase=before').json
        self.assertEqual(state['summary']['confirmed'],1);self.assertEqual(state['summary']['problems'],0)
        self.assertEqual(len(state['history']),2);self.assertEqual(self.count('checklist_runs'),1)
        self.assertEqual(self.post('/v1/admin/checklists',dict(day='2026-10-19',phase='before')).status_code,200)

    def test_checklist_invalid_input_and_required_reason(self):
        self.login('operator')
        self.assertEqual(self.post('/v1/admin/checklists',dict(day='2026-02-30',phase='before')).status_code,400)
        self.assertEqual(self.post('/v1/admin/checklists',dict(day='2026-10-19',phase=[])).status_code,400)
        run,data=self.checklist();path='/v1/admin/checklists/'+run+'/entries'
        self.assertEqual(self.post(path,{**data,'note':''}).status_code,400)
        self.assertEqual(self.post(path,{**data,'assignee':None}).status_code,400)
        self.assertEqual(self.post(path,{**data,'item_id':'not-an-item'}).status_code,400)
        self.assertEqual(self.post(path,data,csrf='bad').status_code,403)


    def plan(self):
        return dict(deployment_os='linux',portal_hostname='wifi.example.test',admin_hostname='admin.example.test',
                    portal_certificate='/etc/festival/portal/fullchain.pem',portal_private_key='/etc/festival/portal/key.pem',
                    admin_certificate='/etc/festival/admin/fullchain.pem',admin_private_key='/etc/festival/admin/key.pem',management_networks=['192.0.2.0/24','2001:db8:1::/64'])

    def test_https_unknowns_remain_blocked_and_no_config_generated(self):
        plan=json.loads((ROOT/'deployment/https-plan.example.json').read_text())
        status=inspect_plan(plan);self.assertFalse(status['plan_complete']);self.assertFalse(status['production_ready'])
        folder=self.home.parent/'unknown-https';write_plan(ROOT/'deployment/https-plan.example.json',folder)
        self.assertTrue((folder/'https-readiness.json').exists());self.assertFalse((folder/'nginx.closed.conf').exists())

    def test_https_closed_plan_separates_management_and_never_forwards(self):
        plan=self.plan();status=inspect_plan(plan);self.assertTrue(status['plan_complete']);self.assertFalse(status['production_ready'])
        config=render_closed_config(plan)
        self.assertNotIn('proxy_pass',config);self.assertIn('deny all;',config);self.assertIn('try_files',config)
        self.assertIn('location ^~ /v1/admin/ { return 404; }',config)
        self.assertIn('TLSv1.2 TLSv1.3',config);self.assertNotIn('$request ',config);self.assertNotIn('$remote_addr',config)
        self.assertFalse(status['certificate_files_inspected'])

    def test_https_plan_accepts_freebsd(self):
        plan={**self.plan(),'deployment_os':'freebsd'};self.assertTrue(inspect_plan(plan)['plan_complete'])
        self.assertIn('Dedicated freebsd nginx',render_closed_config(plan))

    def test_https_injection_and_unrestricted_admin_network_rejected(self):
        for change in [dict(portal_hostname='evil.test; include bad'),dict(admin_private_key='/etc/key;bad'),dict(management_networks=['0.0.0.0/0']),dict(management_networks=['::/0']),dict(deployment_os='windows')]:
            plan={**self.plan(),**change};self.assertFalse(inspect_plan(plan)['plan_complete'])
            with self.assertRaises(ValueError): render_closed_config(plan)

if __name__=='__main__': unittest.main()
