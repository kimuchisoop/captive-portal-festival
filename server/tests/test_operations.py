import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'.deps')]
import json
import secrets
import unittest
from unittest.mock import patch
from urllib.parse import urlencode
from app import uid,utc
from database import Connection,connect,DatabaseError
from jobs import monitor
from workflow_backup import backup_stream as backup
from operations import inspect_grants,mysql_diagnostic,backup_inventory
from ap_profile import inspect_profile
import test_service as service_tests

class OperationalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): service_tests.Tests.setUpClass.__func__(cls)
    setUp=service_tests.Tests.setUp
    tearDown=service_tests.Tests.tearDown
    get=service_tests.Tests.get
    post=service_tests.Tests.post
    login=service_tests.Tests.login
    count=service_tests.Tests.count

    def test_new_routes_require_login(self):
        for path in ('/v1/admin/audit','/v1/admin/storage','/v1/admin/backups','/v1/admin/ap-readiness'):
            self.assertEqual(self.get(path).status_code,401,path)
        self.assertEqual(self.post('/v1/admin/diagnostics').status_code,401)

    def test_viewer_sees_only_aggregate_storage(self):
        self.login('viewer')
        self.assertEqual(self.get('/v1/admin/storage').status_code,200)
        for path in ('/v1/admin/audit','/v1/admin/backups','/v1/admin/ap-readiness'):
            self.assertEqual(self.get(path).status_code,403,path)
        self.assertEqual(self.post('/v1/admin/diagnostics').status_code,403)

    def test_record_role_can_list_backups_but_not_audit_or_diagnostics(self):
        self.login('records')
        self.assertEqual(self.get('/v1/admin/backups').status_code,200)
        self.assertEqual(self.get('/v1/admin/audit').status_code,403)
        self.assertEqual(self.post('/v1/admin/diagnostics').status_code,403)

    def test_audit_filters_and_keyset_pagination_keep_all_rows(self):
        self.login();owner=uid();ids=set()
        with self.s.db(True) as db:
            for _ in range(8):
                self.s.audit(db,owner,'login')
            ids={r[0] for r in db.execute('SELECT id FROM audit WHERE actor=?',(owner,)).fetchall()}
        params={'actor':owner,'action':'login','limit':'2','from':utc(self.s.now()),'until':utc(self.s.now()+1)}
        seen=[]
        while True:
            r=self.get('/v1/admin/audit?'+urlencode(params))
            self.assertEqual(r.status_code,200,r.json)
            seen.extend(row['id'] for row in r.json['items'])
            if not r.json['next_cursor']: break
            params.update(r.json['next_cursor'])
        self.assertEqual(set(seen),ids);self.assertEqual(len(seen),len(set(seen)))
        self.assertEqual(self.count('audit'),13) # four account creations, login, eight fixtures

    def test_audit_date_range_is_half_open(self):
        self.login()
        r=self.get('/v1/admin/audit?'+urlencode({'from':utc(self.s.now()-1),'until':utc(self.s.now())}))
        self.assertEqual(r.json['items'],[])
        r=self.get('/v1/admin/audit?'+urlencode({'from':utc(self.s.now()),'until':utc(self.s.now()+1)}))
        self.assertGreater(len(r.json['items']),0)

    def test_audit_rejects_bad_ranges_and_injection(self):
        self.login()
        for params in ({'limit':'10000'},{'actor':"' OR 1=1"},{'from':'yesterday'},
                       {'before_time':'1'},{'before_time':'1','before_id':'bad'},
                       {'from':utc(self.s.now()),'until':utc(self.s.now())},{'unexpected':'x'}):
            self.assertEqual(self.get('/v1/admin/audit?'+urlencode(params)).status_code,400,params)

    def test_audit_response_never_contains_password_hashes_or_secrets(self):
        self.login();r=self.get('/v1/admin/audit')
        self.assertNotIn(self.password,r.get_data(as_text=True))
        self.assertNotIn('password_hash',r.get_data(as_text=True))
        self.assertIn('settings',[u['label'] for u in r.json['actors']])

    def test_backup_catalog_reports_metadata_and_paginates_without_deleting(self):
        directory=self.home/'backups';directory.mkdir()
        names=[]
        for i in range(3):
            name=f'backup-{self.s.now()+i}-{uid()}.sffbackup';names.append(name)
            (directory/name).write_bytes(b'catalog-only-fixture')
        (directory/'unrecognized-file.txt').write_text('preserve this',encoding='utf-8')
        first=backup_inventory(self.s,limit=2)
        second=backup_inventory(self.s,before=first['next_cursor'],limit=2)
        self.assertEqual(len(first['items']),2);self.assertEqual(len(second['items']),1)
        self.assertEqual(first['total_files'],3);self.assertEqual(first['ignored_entries'],0)
        self.assertEqual(first['other_regular_files'],1)
        self.assertEqual({r['filename'] for r in first['items']+second['items']},set(names))
        self.assertTrue(all(r['verification']=='not_checked' for r in first['items']))
        self.assertEqual(len(list(directory.iterdir())),4)

    def test_backup_catalog_rejects_paths_and_exposes_no_file_contents(self):
        backup(self.s);self.login()
        for params in ({'before':'../session.key'},{'limit':'1000'},{'path':'session.key'}):
            self.assertEqual(self.get('/v1/admin/backups?'+urlencode(params)).status_code,400)
        text=self.get('/v1/admin/backups').get_data(as_text=True)
        self.assertNotIn((self.home/'backup.key').read_text(),text)
        self.assertNotIn(self.s.db_settings['password'],text)

    def test_storage_distinguishes_estimate_application_disk_and_unknown_db_disk(self):
        self.login();r=self.get('/v1/admin/storage')
        self.assertEqual(r.status_code,200)
        self.assertTrue(r.json['database_size_is_estimate'])
        self.assertIsNone(r.json['database_disk_free_bytes'])
        self.assertGreater(r.json['application_disk_total_bytes'],0)
        self.assertEqual(len(r.json['tables']),31)
        self.assertFalse(r.json['automatic_deletion_enabled'])
        self.assertFalse(r.json['thresholds_configured'])

    def test_capacity_warnings_trigger_and_resolve_without_deletion(self):
        file=backup(self.s)
        self.s.config.update(db_warning_bytes=1,backup_warning_bytes=1)
        monitor(self.s)
        with self.s.db() as db:
            self.assertEqual(db.execute("SELECT state FROM notifications WHERE code='database_size_high'").fetchone()[0],'open')
            self.assertEqual(db.execute("SELECT state FROM notifications WHERE code='backup_size_high'").fetchone()[0],'open')
        self.s.config.update(db_warning_bytes=2**60,backup_warning_bytes=2**60)
        monitor(self.s)
        with self.s.db() as db:
            self.assertEqual(db.execute("SELECT state FROM notifications WHERE code='database_size_high'").fetchone()[0],'resolved')
        self.assertTrue(file.exists())

    def test_diagnostic_is_csrf_protected_and_does_not_change_grants(self):
        self.login()
        self.assertEqual(self.post('/v1/admin/diagnostics',csrf='bad').status_code,403)
        with self.s.db() as db: before=[r[0] for r in db.execute('SHOW GRANTS FOR CURRENT_USER').fetchall()]
        r=self.post('/v1/admin/diagnostics');self.assertEqual(r.status_code,200,r.json)
        self.assertFalse(r.json['mutation_performed']);self.assertFalse(r.json['production_ready'])
        self.assertTrue(r.json['audit_saved']);self.assertTrue(r.json['privilege_review']['minimal'],r.json['privilege_review'])  # tests run with the generated least-privilege account
        self.assertTrue((self.home/'diagnostics'/(r.json['report_id']+'.json')).exists())
        self.assertNotIn(self.s.db_settings['password'],r.get_data(as_text=True))
        with self.s.db() as db:
            self.assertEqual(before,[row[0] for row in db.execute('SHOW GRANTS FOR CURRENT_USER').fetchall()])
            self.assertTrue(db.execute("SELECT 1 FROM audit WHERE action='diagnostic_run'").fetchone())


    def test_unresolved_roles_or_extra_scopes_are_not_marked_minimal(self):
        good=['GRANT USAGE ON *.* TO `app`@`localhost`','GRANT SELECT, INSERT, UPDATE, DELETE ON `festival`.* TO `app`@`localhost`']
        self.assertFalse(inspect_grants(good,'festival','NONE')['minimal'])
        for extra in ('GRANT ALL PRIVILEGES ON *.* TO `app`@`localhost`',
                      'GRANT SELECT ON `other`.* TO `app`@`localhost`',
                      'GRANT `application_role`@`%` TO `app`@`localhost`'):
            self.assertFalse(inspect_grants(good+[extra],'festival','NONE')['minimal'])
        self.assertFalse(inspect_grants(good,'festival',"`application_role`@`%`")['minimal'])

    def test_diagnostic_failure_redacts_connector_exception(self):
        with patch('operations.connect',side_effect=DatabaseError('secret='+self.s.db_settings['password'])):
            r=mysql_diagnostic(self.s.db_settings)
        self.assertFalse(r['connected']);self.assertNotIn(self.s.db_settings['password'],json.dumps(r))

    def test_ap_unknown_profile_does_not_infer_sku_or_os(self):
        self.login();r=self.get('/v1/admin/ap-readiness')
        self.assertEqual(r.status_code,200);self.assertEqual(len(r.json['missing']),6)
        self.assertIsNone(r.json['facts']['sku']);self.assertFalse(r.json['live_verified'])
        self.assertEqual(r.json['adapter'],'disconnected')

    def test_complete_inventory_does_not_enable_adapter(self):
        profile=dict(product_model='IAP-315',sku='inventory-example-only',os_family='Aruba Instant',
                     os_version='example-only',management_mode='instant',manager_address='192.0.2.1',production_ready=True)
        path=self.home/'device-profile.json';path.write_text(json.dumps(profile),encoding='utf-8')
        r=inspect_profile(path)
        self.assertTrue(r['identity_complete']);self.assertFalse(r['production_ready'])
        self.assertFalse(r['live_verified']);self.assertTrue(all(c['status']=='not_verified' for c in r['required_capabilities']))

    def test_malformed_ap_profile_is_reported_without_crashing(self):
        path=self.home/'device-profile.json';path.write_text('{',encoding='utf-8')
        r=inspect_profile(path);self.assertTrue(r['errors']);self.assertFalse(r['identity_complete'])

if __name__=='__main__': unittest.main(verbosity=2)
