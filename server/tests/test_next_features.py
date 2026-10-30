import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'.deps')]
import base64
import hashlib
import json
import secrets
import shutil
import unittest
from cryptography.fernet import Fernet
from app import Service,uid,digest
from database import initialize_schema,transaction
from jobs import backup,monitor,notify,restore,LEGACY_TABLES
from manage import initialize
from mfa import enroll,totp
from migrations import upgrade_to_v4 as upgrade_from_v2
from operator_features import sample_storage,storage_history
from mysql_fixture import new_database
import test_service as service_tests

class NextFeaturesTests(unittest.TestCase):
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

    def draft(self):
        r=self.post('/v1/admin/terms-revisions',dict(version='test-2',policy_version='policy-2',ja='新しい規約\n<script>alert(1)</script>',en='Updated terms'))
        self.assertEqual(r.status_code,201,r.json)
        return self.get('/v1/admin/terms-revisions/'+r.json['revision_id']).json

    def publish(self,r,previous=None,key=None):
        return self.post('/v1/admin/terms-publications',dict(revision_id=r['id'],preview_sha256=r['preview_sha256'],expected_publication_id=previous),key=key)

    def test_features_auth_roles_and_csrf(self):
        for p in ('notification-cases','terms-revisions','storage-history','mfa-status'):
            self.assertEqual(self.get('/v1/admin/'+p).status_code,401)
        self.login('viewer')
        self.assertEqual(self.get('/v1/admin/notification-cases').status_code,200)
        self.assertEqual(self.get('/v1/admin/storage-history').status_code,200)
        self.assertEqual(self.get('/v1/admin/terms-revisions').status_code,403)
        self.assertEqual(self.post('/v1/admin/terms-revisions').status_code,403)
        self.assertEqual(self.post('/v1/admin/notification-cases/'+uid()).status_code,403)
        self.login()
        self.assertEqual(self.post('/v1/admin/terms-revisions',csrf='invalid').status_code,403)

    def test_handover_stale_retries_and_recurrence(self):
        monitor(self.s);self.login('operator')
        n=self.get('/v1/admin/notification-cases').json['items'][0]
        d=dict(generation=n['generation'],expected_update_id=None,assignee=None,status='in_progress',note='会場担当へ確認中')
        key=uid();path='/v1/admin/notification-cases/'+n['id']
        first=self.post(path,d,key=key);self.assertEqual(first.status_code,201,first.json)
        self.assertEqual(self.post(path,d,key=key).json,first.json)
        self.assertEqual(self.post(path,d).status_code,409)
        state=self.get('/v1/admin/notification-cases').json
        row=next(x for x in state['items'] if x['id']==n['id'])
        self.assertEqual(row['workflow']['status'],'in_progress')
        self.assertEqual(row['condition'],n['condition'])
        with self.s.db(True) as db:
            notify(db,self.s.now(),n['code'],'',False);notify(db,self.s.now(),n['code'],'再発')
        state=self.get('/v1/admin/notification-cases').json
        row=next(x for x in state['items'] if x['id']==n['id'])
        self.assertEqual(row['generation'],n['generation']+1);self.assertIsNone(row['workflow'])
        self.assertEqual(len(state['history']),1)

    def test_handover_invalid_assignee_and_input(self):
        monitor(self.s);self.login()
        n=self.get('/v1/admin/notification-cases').json['items'][0]
        d=dict(generation=n['generation'],expected_update_id=None,assignee=uid(),status='handled',note='確認済み')
        path='/v1/admin/notification-cases/'+n['id']
        self.assertEqual(self.post(path,d).status_code,400)
        d.update(assignee=None,note='x'*1001)
        self.assertEqual(self.post(path,d).status_code,400)
        self.assertEqual(self.count('notification_updates'),0)

    def test_terms_draft_does_not_publish_and_preview_is_plain_data(self):
        original=self.s.terms('ja');self.login();r=self.draft()
        self.assertEqual(self.s.terms('ja'),original)
        self.assertIn('<script>',r['ja'])
        self.assertNotIn('actor',r)
        key=uid();d=dict(version='v',policy_version='p',ja='日本語',en='English')
        a=self.post('/v1/admin/terms-revisions',d,key=key)
        b=self.post('/v1/admin/terms-revisions',d,key=key)
        self.assertEqual(a.json,b.json);self.assertEqual(self.count('terms_revisions'),2)

    def test_terms_publish_conflict_and_old_consent_preserved(self):
        consent=self.consent();old_terms=self.s.terms('ja');old_payload=self.consent_data()
        self.login();r=self.draft();first=self.publish(r,key=uid())
        self.assertEqual(first.status_code,201,first.json)
        self.assertEqual(self.s.terms('ja')['document_id'],r['id'])
        self.assertEqual(self.get('/v1/public').json['terms']['text'],r['ja'])
        self.assertEqual(self.get('/v1/admin/settings').json['terms_version'],r['version'])
        self.assertEqual(self.publish(r).status_code,409)
        with self.s.db() as db:
            saved=db.execute('SELECT * FROM consents WHERE id=?',(consent['consent_id'],)).fetchone()
            self.assertEqual(saved['terms_document_id'],old_terms['document_id'])
            self.assertEqual(saved['terms_sha256'],old_terms['sha256'])
        self.visitor()
        self.assertEqual(self.post('/v1/consents',old_payload).status_code,409)

    def test_terms_mismatched_preview_rejected(self):
        self.login();r=self.draft();r['preview_sha256']='0'*64
        self.assertEqual(self.publish(r).status_code,409)
        self.assertEqual(self.count('terms_publications'),0)

    def test_new_history_and_revisions_are_immutable(self):
        from database import DatabaseError
        self.login();r=self.draft();self.publish(r)
        with self.assertRaises(DatabaseError):
            with self.s.db(True) as db: db.execute("UPDATE terms_revisions SET ja='changed' WHERE id=?",(r['id'],))
        with self.assertRaises(DatabaseError):
            with self.s.db(True) as db: db.execute("UPDATE terms_publications SET actor='changed'")

    def test_terms_unicode_limits_supported(self):
        self.login()
        r=self.post('/v1/admin/terms-revisions',dict(version='v',policy_version='p',ja='あ'*5000,en='い'*5000))
        # JSON escaping can use 60 KiB; the HTTP boundary explicitly supports this bounded payload.
        self.assertEqual(r.status_code,201,r.json)

    def test_growth_history_no_forecast_before_real_span(self):
        sample=dict(database_allocated_bytes=1000,backup_bytes=200,application_disk_free_bytes=10000)
        sample_storage(self.s,sample);sample_storage(self.s,sample)
        self.assertEqual(self.count('storage_samples'),1)
        self.assertIsNone(storage_history(self.s)['forecast'])
        self.clock.value+=43200;sample_storage(self.s,{**sample,'backup_bytes':300})
        self.clock.value+=43200;sample_storage(self.s,{**sample,'backup_bytes':400})
        f=storage_history(self.s)['forecast']
        self.assertEqual(f['backup']['bytes_per_day'],200)
        self.assertIsNone(f['backup']['days_to_warning'])

    def test_rfc6238_reference_vectors(self):
        secret=base64.b32encode(b'12345678901234567890').decode()
        for when,expected in [(59,'94287082'),(1111111109,'07081804'),(1111111111,'14050471'),(20000000000,'65353130')]:
            self.assertEqual(totp(secret,when//30,8),expected)

    def setup_mfa(self):
        secret=base64.b32encode(secrets.token_bytes(20)).decode()
        codes=enroll(self.s,'settings',secret,totp(secret,self.clock.value//30))
        self.clock.value+=30
        self.csrf=self.post('/v1/admin/session').json['csrf_token']
        r=self.post('/v1/admin/login',dict(username='settings',password=self.password))
        self.assertTrue(r.json['mfa_required']);self.assertFalse(r.json['authenticated'])
        self.csrf=r.json['csrf_token'];return secret,codes

    def test_mfa_pending_cannot_access_admin_and_replay_rejected(self):
        secret,_=self.setup_mfa()
        self.assertEqual(self.get('/v1/admin/overview').status_code,401)
        self.assertEqual(self.get('/v1/admin/mfa-status').status_code,401)
        code=totp(secret,self.clock.value//30)
        r=self.post('/v1/admin/mfa',dict(code=code));self.assertEqual(r.status_code,200,r.json)
        self.csrf=r.json['csrf_token'];self.assertEqual(self.get('/v1/admin/overview').status_code,200)
        status=self.get('/v1/admin/mfa-status').json
        self.assertTrue(status['enabled']);self.assertEqual(status['recovery_codes_remaining'],8)
        self.assertNotIn(secret,json.dumps(status))
        self.post('/v1/admin/logout')
        self.csrf=self.post('/v1/admin/session').json['csrf_token']
        self.csrf=self.post('/v1/admin/login',dict(username='settings',password=self.password)).json['csrf_token']
        self.assertEqual(self.post('/v1/admin/mfa',dict(code=code)).status_code,401)

    def test_mfa_recovery_one_use_and_secret_encrypted(self):
        secret,codes=self.setup_mfa()
        with self.s.db() as db:
            self.assertNotIn(secret,db.execute('SELECT secret_ciphertext FROM mfa_settings').fetchone()[0])
            self.assertNotIn(codes[0],str(db.execute('SELECT * FROM mfa_recovery').fetchall()))
        r=self.post('/v1/admin/mfa',dict(code=codes[0]));self.assertEqual(r.status_code,200)
        self.csrf=r.json['csrf_token'];self.assertEqual(self.get('/v1/admin/mfa-status').json['recovery_codes_remaining'],7)
        self.post('/v1/admin/logout');self.csrf=self.post('/v1/admin/session').json['csrf_token']
        self.csrf=self.post('/v1/admin/login',dict(username='settings',password=self.password)).json['csrf_token']
        self.assertEqual(self.post('/v1/admin/mfa',dict(code=codes[0])).status_code,401)

    def test_mfa_rate_limit_survives_new_password_challenge(self):
        _,_=self.setup_mfa()
        for _ in range(5): self.assertEqual(self.post('/v1/admin/mfa',dict(code='invalid')).status_code,401)
        self.assertEqual(self.post('/v1/admin/mfa',dict(code='invalid')).status_code,429)
        self.csrf=self.post('/v1/admin/login',dict(username='settings',password=self.password)).json['csrf_token']
        self.assertEqual(self.post('/v1/admin/mfa',dict(code='invalid')).status_code,429)

    def test_mfa_challenge_expiry(self):
        secret,_=self.setup_mfa();self.clock.value+=121
        self.assertEqual(self.post('/v1/admin/mfa',dict(code=totp(secret,self.clock.value//30))).status_code,403)

    def legacy(self):
        settings=new_database();initialize_schema(settings,ROOT/'schema-v2.sql')
        home=self.home.parent/('legacy-'+uid());shutil.copytree(self.home,home)
        (home/'mysql.json').write_text(json.dumps(settings),encoding='utf-8')
        with transaction(settings,True) as db:
            db.execute('INSERT INTO audit VALUES (?,?,?,?,?,?)',(uid(),'local_cli','legacy_log',None,self.s.now(),self.s.now()+100))
        return settings,home

    def test_explicit_upgrade_keeps_records_and_rejects_legacy_start(self):
        settings,home=self.legacy()
        with self.assertRaises(ValueError): Service(home)
        self.assertTrue(upgrade_from_v2(settings,home))
        s=Service(home)
        with s.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM audit').fetchone()[0],1)
            self.assertEqual(db.execute("SELECT value FROM meta WHERE name='schema_version'").fetchone()[0],'4')
        self.assertFalse(upgrade_from_v2(settings,home))

    def test_legacy_backup_restores_and_upgrades_without_deletion(self):
        settings,home=self.legacy()
        snapshot=dict(format='festival-wifi-mysql-backup',schema_version='2',created_at=self.s.now(),
                      schema_sha256=hashlib.sha256((ROOT/'schema-v2.sql').read_bytes()).hexdigest(),tables={},columns={})
        with transaction(settings) as db:
            for table in LEGACY_TABLES:
                snapshot['columns'][table]=[r['Field'] for r in db.execute('SHOW COLUMNS FROM `'+table+'`').fetchall()]
                snapshot['tables'][table]=db.execute('SELECT * FROM `'+table+'`').fetchall()
        source=home/'legacy.fernet';source.write_bytes(Fernet((home/'backup.key').read_bytes()).encrypt(json.dumps(snapshot).encode()))
        dest=home.parent/('restored-'+uid());restore(source,home/'backup.key',dest,new_database())
        s=initialize(dest,restored=True)
        with s.db() as db: self.assertEqual(db.execute("SELECT count(*) FROM audit WHERE action='legacy_log'").fetchone()[0],1)
        self.assertTrue(source.exists());self.assertFalse(s.config['local_intake_enabled'])

    def test_new_backup_includes_features_and_requires_mfa_reenrollment(self):
        self.login();r=self.draft();self.publish(r);monitor(self.s)
        secret=base64.b32encode(secrets.token_bytes(20)).decode()
        enroll(self.s,'settings',secret,totp(secret,self.clock.value//30))
        path=backup(self.s);dest=self.home.parent/('recover-new-'+uid())
        restore(path,self.home/'backup.key',dest,new_database());s=initialize(dest,restored=True)
        with s.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM terms_revisions').fetchone()[0],1)
            self.assertGreater(db.execute('SELECT count(*) FROM storage_samples').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT needs_reset FROM mfa_settings').fetchone()[0],1)
        self.assertEqual(s.terms('ja')['document_id'],r['id'])

if __name__=='__main__': unittest.main()
