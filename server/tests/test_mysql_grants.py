"""Generated least-privilege grants (tools/mysql_grants.py) against the schema-five contract and a real MySQL."""
import json,secrets,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT.parent/'tools'))
import mysql_grants
from operations import inspect_grants
from workflow_database import maintenance_findings

class GeneratedGrantContractTests(unittest.TestCase):
    def test_runtime_grants_match_contract(self):
        lines=['GRANT USAGE ON *.* TO `svc`@`%`']+[s.rstrip(';').replace("'svc'@'%'",'`svc`@`%`') for s in mysql_grants.runtime_statements('app_db','svc','%')]
        result=inspect_grants(lines,'app_db','NONE')
        self.assertTrue(result['minimal'],result)

    def test_extra_or_missing_privilege_is_reported(self):
        lines=[s.rstrip(';') for s in mysql_grants.runtime_statements('app_db','svc','%')]
        self.assertFalse(inspect_grants(lines[1:],'app_db','NONE')['minimal'])
        self.assertFalse(inspect_grants(lines+['GRANT DROP ON `app_db`.`meta` TO `svc`@`%`'],'app_db','NONE')['minimal'])

    def test_unsafe_names_rejected(self):
        for args in [('db`x','u','%'),('db','u\'x','%'),('db','u','h\'x')]:
            with self.assertRaises(ValueError):mysql_grants.runtime_statements(*args)

class InitializationPrecheckTests(unittest.TestCase):
    def grants(self):
        return [s.rstrip(';') for s in mysql_grants.maintenance_statements('app_db','mnt','%')]

    def test_generated_maintenance_grants_pass(self):
        self.assertEqual(maintenance_findings(self.grants(),'app_db',1,1,'NONE'),[])

    def test_missing_update_and_untrusted_binlog_are_reported(self):
        lines=[l.replace(', UPDATE','') if '`meta`' in l else l for l in self.grants()]
        findings=maintenance_findings(lines,'app_db',1,0,'NONE')
        self.assertTrue(any('UPDATE' in f for f in findings),findings)
        self.assertTrue(any('log_bin_trust_function_creators' in f for f in findings),findings)
        self.assertEqual(maintenance_findings(self.grants(),'app_db',0,0,'NONE'),[])  # binlog off

    def test_database_or_global_all_privileges_pass(self):
        self.assertEqual(maintenance_findings(['GRANT ALL PRIVILEGES ON `app_db`.* TO `m`@`%`'],'app_db',0,0,'NONE'),[])
        self.assertEqual(maintenance_findings(['GRANT ALL PRIVILEGES ON *.* TO `root`@`%`'],'app_db',1,0,'NONE'),[])
        self.assertTrue(maintenance_findings(['GRANT ALL PRIVILEGES ON `other`.* TO `m`@`%`'],'app_db',0,0,'NONE'))

class GeneratedGrantMySQLTests(unittest.TestCase):
    def setUp(self):
        from mysql_fixture import credentials,PreservedDirectory
        self.c,_=credentials();self.temp=PreservedDirectory();self.created=[]

    def root(self,statements):
        import mysql.connector
        raw=mysql.connector.connect(**{k:self.c[k] for k in ('host','port','user','password')},use_pure=True)
        try:
            cursor=raw.cursor()
            for statement in statements:cursor.execute(statement.rstrip(';'))
            cursor.close()
        finally:raw.close()

    def test_maintenance_init_then_runtime_grants_are_minimal_and_sufficient(self):
        from security import protect_directory
        from jobs import secure_new_file
        from workflow_cli import initialize
        from operations import mysql_diagnostic
        from app import create_app
        import mysql.connector
        raw=mysql.connector.connect(**{k:self.c[k] for k in ('host','port','user','password')},use_pure=True)
        try:
            cursor=raw.cursor();cursor.execute('SELECT @@log_bin,@@log_bin_trust_function_creators');log_bin,trusted=cursor.fetchone();cursor.close()
        finally:raw.close()
        if log_bin and not trusted:
            self.skipTest('Schema triggers need log_bin_trust_function_creators=ON (or binlog disabled) for a non-SUPER maintenance account')
        token=secrets.token_hex(5);database='grant_'+token;service='svc_'+token;maint='mnt_'+token
        passwords={service:secrets.token_urlsafe(18),maint:secrets.token_urlsafe(18)}
        self.root(['CREATE DATABASE `'+database+'` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin']+
                  ["CREATE USER '"+u+"'@'%' IDENTIFIED BY '"+p+"'" for u,p in passwords.items()]+
                  mysql_grants.maintenance_statements(database,maint,'%'))
        base=dict(host=self.c['host'],port=self.c['port'],database=database)
        runtime={**base,'user':service,'password':passwords[service]}
        folder=Path(self.temp.name)/'maintenance';folder.mkdir();protect_directory(folder)
        secure_new_file(folder/'maintenance.json',json.dumps({**base,'user':maint,'password':passwords[maint]}).encode())
        home=Path(self.temp.name)/'data'
        self.assertIsNone(initialize(home,True,db_settings=runtime,maintenance_file=folder/'maintenance.json',open_service=False))
        self.root(mysql_grants.runtime_statements(database,service,'%'))
        result=mysql_diagnostic(runtime)
        review=next(c for c in result['checks'] if c['code']=='privileges')
        self.assertEqual(review['status'],'pass',result)
        client=create_app(home).test_client()
        self.assertEqual(client.get('/v1/public?lang=ja',base_url='http://127.0.0.1:8890').status_code,200)

    def accounts(self,maintenance_privileges=None):
        from security import protect_directory
        from jobs import secure_new_file
        token=secrets.token_hex(5);database='pre_'+token;maint='mnt_'+token;password=secrets.token_urlsafe(18)
        grants=mysql_grants.maintenance_statements(database,maint,'%') if maintenance_privileges is None else ['GRANT '+maintenance_privileges+' ON `'+database+"`.* TO '"+maint+"'@'%'"]
        self.root(['CREATE DATABASE `'+database+'`',"CREATE USER '"+maint+"'@'%' IDENTIFIED BY '"+password+"'"]+grants)
        base=dict(host=self.c['host'],port=self.c['port'],database=database)
        folder=Path(self.temp.name)/('m-'+token);folder.mkdir();protect_directory(folder)
        secure_new_file(folder/'maintenance.json',json.dumps({**base,'user':maint,'password':password}).encode())
        return {**base,'user':'svc_'+token,'password':'unused-'+token},folder/'maintenance.json',database

    def test_precheck_refuses_before_creating_anything(self):
        from workflow_cli import initialize
        runtime,maintenance,database=self.accounts('SELECT, INSERT')
        home=Path(self.temp.name)/'refused'
        with self.assertRaisesRegex(ValueError,'Initialization not started'):initialize(home,db_settings=runtime,maintenance_file=maintenance,open_service=False)
        self.assertFalse(home.exists())
        runtime,maintenance,database=self.accounts()
        # Table-level grants only show the app's own tables, so emptiness is checked for those.
        self.root(['CREATE TABLE `'+database+'`.`meta` (id INT)'])
        with self.assertRaisesRegex(ValueError,'not empty'):initialize(home,db_settings=runtime,maintenance_file=maintenance,open_service=False)
        self.assertFalse(home.exists())

    def test_failed_schema_creation_is_recorded_not_deleted(self):
        from unittest.mock import patch
        from database import transaction
        import workflow_cli
        runtime,maintenance,database=self.accounts()
        def partial(settings,schema_file):
            with transaction(settings,True) as db:db.execute('CREATE TABLE meta (k INT PRIMARY KEY)')
            raise RuntimeError('simulated DDL failure')
        home=Path(self.temp.name)/'failed'
        with patch.object(workflow_cli,'initialize_schema',partial):
            with self.assertRaisesRegex(ValueError,'after creating 1 tables'):
                workflow_cli.initialize(home,db_settings=runtime,maintenance_file=maintenance,open_service=False)
        record=json.loads((home/'initialization.failed.json').read_text(encoding='utf-8'))
        self.assertEqual(record['tables_created'],['meta']);self.assertIn('simulated DDL failure',record['error'])
        self.assertTrue((home/'initialization.incomplete').exists())

if __name__=='__main__':unittest.main()
