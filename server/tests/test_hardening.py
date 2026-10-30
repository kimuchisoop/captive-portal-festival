import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import json,hashlib,unittest
from unittest.mock import patch
from werkzeug.test import Client
from werkzeug.wrappers import Response
from app import Service,create_app
from transport import HTTPSBoundary,validate_transport
from capacity_policy import make_plan,apply_plan,GIB
from jobs import monitor
import test_service as service_tests

SETTINGS=dict(enabled=True,portal_origin='https://wifi.example.org',admin_origin='https://admin.example.org',trusted_proxy='127.0.0.1')

class ProxyTests(unittest.TestCase):
    def client(self):
        def endpoint(env,start):
            return Response(json.dumps(dict(scheme=env['wsgi.url_scheme'],peer=env['REMOTE_ADDR'],host=env['HTTP_HOST'],forwarded=any(k.startswith('HTTP_X_FORWARDED_') for k in env))))(env,start)
        return Client(HTTPSBoundary(endpoint,SETTINGS),Response)
    def get(self,path='/',host='wifi.example.org',peer='127.0.0.1',extra=None):
        return self.client().get(path,base_url='http://'+host,headers={'X-Forwarded-Proto':'https','X-Forwarded-For':'192.0.2.1',**(extra or {})},environ_overrides={'REMOTE_ADDR':peer})
    def test_single_proxy_rewrites_scheme_and_ip_and_removes_headers(self):
        r=self.get();self.assertEqual(r.status_code,200);self.assertEqual(json.loads(r.text),dict(scheme='https',peer='192.0.2.1',host='wifi.example.org',forwarded=False))
    def test_untrusted_peers_refused(self):
        for peer in ('192.0.2.4','::1',''):
            self.assertEqual(self.get(peer=peer).status_code,400)
    def test_missing_http_or_multiple_proto_refused(self):
        for value in ('','http','https,http','HTTPS'):
            self.assertEqual(self.get(extra={'X-Forwarded-Proto':value}).status_code,400)
    def test_chain_and_invalid_ip_refused(self):
        for value in ('','192.0.2.1, 10.0.0.1','invalid','192.0.2.1:12'):
            self.assertEqual(self.get(extra={'X-Forwarded-For':value}).status_code,400)
    def test_forwarded_authority_and_prefix_refused(self):
        for name in ('Forwarded','X-Forwarded-Host','X-Forwarded-Port','X-Forwarded-Prefix','X-Forwarded-Server'):
            self.assertEqual(self.get(extra={name:'evil'}).status_code,400)
    def test_public_cannot_reach_admin_health_or_encoded_admin(self):
        for path in ('/admin','/admin/','/v1/admin/session','/v1/admin','/health/live','/%61dmin','/v1%2fadmin/session'):
            self.assertEqual(self.get(path).status_code,400,path)
    def test_admin_cannot_reach_portal_apis(self):
        for path in ('/','/v1/public','/v1/session'):
            self.assertEqual(self.get(path,host='admin.example.org').status_code,400)
    def test_static_allowed_on_both_hosts_and_host_not_inferred(self):
        self.assertEqual(self.get('/static/style.css',host='admin.example.org').status_code,200)
        for host in ('evil.example.org','127.0.0.1:8890','wifi.example.org:443'):
            self.assertEqual(self.get(host=host).status_code,400)
    def test_https_settings_require_disabled_intake_and_exact_origins(self):
        c=dict(https_transport=SETTINGS,local_intake_enabled=False)
        validate_transport(c)
        with self.assertRaises(ValueError): validate_transport(dict(c,local_intake_enabled=True))
        for origin in ('http://wifi.example.org','https://wifi.example.org/','https://wifi.example.org:443','https://user@wifi.example.org','https://wifi.example.org?x=1'):
            with self.assertRaises(ValueError): validate_transport(dict(c,https_transport=dict(SETTINGS,portal_origin=origin)))
        for proxy in ('*','10.0.0.1','127.0.0.0/8'):
            with self.assertRaises(ValueError): validate_transport(dict(c,https_transport=dict(SETTINGS,trusted_proxy=proxy)))

class HardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): service_tests.Tests.setUpClass.__func__(cls)
    setUp=service_tests.Tests.setUp
    tearDown=service_tests.Tests.tearDown
    get=service_tests.Tests.get
    post=service_tests.Tests.post
    login=service_tests.Tests.login
    count=service_tests.Tests.count

    def https_client(self):
        config=self.s.config.copy();config.update(local_intake_enabled=False,https_transport=SETTINGS)
        (self.home/'config.json').write_text(json.dumps(config),encoding='utf-8')
        app=create_app(self.home,self.clock)
        return app.test_client()
    def secure_post(self,c,path,body=None,csrf=None,origin='https://admin.example.org'):
        return c.post(path,base_url=origin,json=body or {},headers={'Origin':origin,'X-Forwarded-Proto':'https','X-Forwarded-For':'192.0.2.50','X-CSRF-Token':csrf or ''},environ_overrides={'REMOTE_ADDR':'127.0.0.1'})
    def test_https_admin_login_cookie_and_logout_cookie_are_secure(self):
        c=self.https_client();r=self.secure_post(c,'/v1/admin/session');self.assertEqual(r.status_code,200)
        cookie=r.headers['Set-Cookie'];self.assertIn('Secure;',cookie);self.assertIn('HttpOnly;',cookie);self.assertIn('SameSite=Strict',cookie);self.assertNotIn('Domain=',cookie)
        r=self.secure_post(c,'/v1/admin/login',dict(username='settings',password=self.password),r.json['csrf_token']);self.assertTrue(r.json['authenticated'])
        r=self.secure_post(c,'/v1/admin/logout',csrf=r.json['csrf_token']);self.assertEqual(r.status_code,200);self.assertIn('Secure;',r.headers['Set-Cookie']);self.assertIn('max-age=3600',r.headers['Strict-Transport-Security'])
    def test_https_cross_origin_post_rejected(self):
        c=self.https_client()
        r=c.post('/v1/admin/session',base_url='https://admin.example.org',json={},headers={'Origin':'https://wifi.example.org','X-Forwarded-Proto':'https','X-Forwarded-For':'192.0.2.1'})
        self.assertEqual(r.status_code,403);self.assertEqual(r.json['code'],'origin_invalid')
    def test_https_intake_still_disabled_and_no_direct_http(self):
        c=self.https_client();self.assertEqual(c.get('/admin',base_url='http://127.0.0.1:8890').status_code,400)
        r=c.get('/v1/public',base_url='https://wifi.example.org',headers={'X-Forwarded-Proto':'https','X-Forwarded-For':'192.0.2.1'})
        self.assertEqual(r.status_code,200);self.assertEqual(r.json['service_state'],'intake_disabled');self.assertFalse(r.json['production_enabled'])
    def test_local_headers_cannot_change_origin(self):
        r=self.client.post('/v1/admin/session',base_url=service_tests.ORIGIN,json={},headers={'Origin':'https://admin.example.org','X-Forwarded-Proto':'https','X-Forwarded-Host':'admin.example.org'})
        self.assertEqual(r.status_code,403)
    def test_capacity_plan_readonly_and_apply_keeps_history(self):
        original=(self.home/'config.json').read_bytes();before=self.count('audit');plan=make_plan(self.s)
        self.assertEqual((self.home/'config.json').read_bytes(),original);self.assertEqual(self.count('audit'),before)
        self.assertGreaterEqual(plan['limits']['db_warning_bytes'],GIB);apply_plan(self.s,plan)
        loaded=Service(self.home,self.clock);self.assertEqual(loaded.config['min_free_bytes'],5*GIB)
        self.assertFalse(loaded.config['automatic_deletion_enabled']);self.assertEqual(self.count('audit'),before+2)
        self.assertTrue(any(p.read_bytes()==original for p in (self.home/'configuration-history').glob('*-before.json')))
    def test_capacity_stale_cross_target_and_invalid_rejected(self):
        plan=make_plan(self.s)
        with self.assertRaises(ValueError): apply_plan(self.s,dict(plan,target_hash='other'))
        with self.assertRaises(ValueError): apply_plan(self.s,dict(plan,limits=dict(plan['limits'],min_free_bytes=True)))
        (self.home/'config.json').write_bytes((self.home/'config.json').read_bytes()+b'\n')
        with self.assertRaises(ValueError): apply_plan(self.s,plan)
    def test_capacity_apply_refuses_running_service(self):
        runtime=self.home/'runtime';runtime.mkdir();(runtime/'current.json').write_text(json.dumps(dict(state='running')))
        with self.assertRaises(ValueError): apply_plan(self.s,make_plan(self.s))
    def test_capacity_warning_and_resolution_keep_records(self):
        self.s.config.update(db_warning_bytes=1,backup_warning_bytes=1)
        from jobs import backup
        backup(self.s);monitor(self.s)
        with self.s.db() as db:
            self.assertEqual(db.execute("SELECT state FROM notifications WHERE code='database_size_high'").fetchone()[0],'open')
        self.s.config.update(db_warning_bytes=2**60,backup_warning_bytes=2**60);monitor(self.s)
        with self.s.db() as db:
            self.assertEqual(db.execute("SELECT state FROM notifications WHERE code='database_size_high'").fetchone()[0],'resolved')
        self.assertEqual(len(list((self.home/'backups').glob('*.sffbackup'))),1)
    def test_admin_navigation_hooks_and_panels_present(self):
        text=self.get('/admin').get_data(as_text=True)
        for name in ('view-event','view-records','view-maintenance','admin-navigation.js','nav-records'): self.assertIn(name,text)

if __name__=='__main__': unittest.main()
