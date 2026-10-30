"""Generated least-privilege grants (tools/mysql_grants.py) against the schema-five contract and a real MySQL."""
import json,secrets,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT.parent/'tools'))
import mysql_grants
from operations import inspect_grants

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

if __name__=='__main__':unittest.main()
