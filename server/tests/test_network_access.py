"""Stage 3 wiring: guest entry by address, batched PORTAL-AUTHED changes, expiry and failures against a fake core-rt."""
import sys,io,json,tempfile,time,unittest
from pathlib import Path
from urllib.error import URLError
from urllib.parse import parse_qs
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'.deps'))
from network_access import validate,access_deadline,process_due,source_ref
from app import create_app,uid,timestamp,utc

KEY='fixture-only-not-a-real-key'
PORTAL='https://wifi.example.org';ADMIN='https://admin.example.org'
HTTPS=dict(enabled=True,portal_origin=PORTAL,admin_origin=ADMIN,trusted_proxy='127.0.0.1')
VYOS=dict(enabled=True,api_origin='https://core-rt.example.test',api_key_file='vyos-api.key',ca_file=None,guest_networks=['192.0.2.0/24'],access_seconds=7200)

class Answer(io.BytesIO):
    def __enter__(self):return self
    def __exit__(self,*a):self.close()

class FakeRouter:
    """Like VyOS: one request may carry a list of commands committed together; deleting a missing address fails."""
    def __init__(self):self.members=set();self.commits=[];self.fail=None
    def __call__(self,request,timeout,context):
        if self.fail:raise self.fail
        form=parse_qs(request.data.decode());data=json.loads(form['data'][0])
        if request.full_url.endswith('/retrieve'):
            if not self.members:return self.answer(False,error='Configuration under specified path is empty')
            listed=sorted(self.members);return self.answer(True,{'address':listed[0] if len(listed)==1 else listed})
        commands=data if isinstance(data,list) else [data];self.commits.append(commands)
        for c in commands:
            if c['op']=='delete' and c['path'][-1] not in self.members:return self.answer(False,error='Nothing to delete')
        for c in commands:(self.members.add if c['op']=='set' else self.members.discard)(c['path'][-1])
        return self.answer(True)
    def answer(self,success,data=None,error=None):return Answer(json.dumps({'success':success,'data':data,'error':error}).encode())

class Clock:
    def __init__(self):self.value=int(time.time())
    def __call__(self):return self.value

class Settings(unittest.TestCase):
    """No MySQL: the settings checks and the deadline arithmetic."""
    def test_disabled_or_missing_is_off(self):
        self.assertIsNone(validate({},'.'));self.assertIsNone(validate({'vyos_portal':dict(VYOS,enabled=False)},'.'))
    def test_needs_https_and_strict_values(self):
        with self.assertRaises(ValueError):validate({'vyos_portal':VYOS,'https_transport':dict(HTTPS,enabled=False)},'.')
        for change in (dict(api_key_file='../key'),dict(api_key_file='a/b'),dict(guest_networks=[]),dict(guest_networks=['192.0.2.1/33']),
                       dict(access_seconds=30),dict(access_seconds='7200'),dict(extra=1)):
            with self.assertRaises(ValueError,msg=change):validate({'vyos_portal':dict(VYOS,**change),'https_transport':HTTPS},'.')
    def test_key_file_must_exist(self):
        with tempfile.TemporaryDirectory() as home:
            with self.assertRaises(ValueError):validate({'vyos_portal':VYOS,'https_transport':HTTPS},home)
            (Path(home)/'vyos-api.key').write_text(KEY,encoding='utf-8');self.assertTrue(validate({'vyos_portal':VYOS,'https_transport':HTTPS},home)['enabled'])
    def test_only_guest_ipv4_addresses(self):
        settings=dict(VYOS,guest_networks=[__import__('ipaddress').IPv4Network('192.0.2.0/24')])
        self.assertEqual(source_ref(settings,'192.0.2.9'),'ipv4:192.0.2.9');self.assertEqual(source_ref(settings,'::ffff:192.0.2.9'),'ipv4:192.0.2.9')
        for other in ('127.0.0.1','198.51.100.1','2001:db8::1','',None,'not-an-ip'):self.assertIsNone(source_ref(settings,other))
    def test_deadline_cut_at_closing_and_window_end(self):
        class S:pass
        s=S();s.network=S();s.network.settings=dict(access_seconds=7200)
        now=timestamp('2026-10-31T06:30:00Z')  # 15:30 JST
        s.config=dict(service_end_utc='2026-11-01T08:00:00Z',daily_service_hours=dict(open='10:00',close='17:00',utc_offset_minutes=540))
        self.assertEqual(utc(access_deadline(s,now)),'2026-10-31T08:00:00Z')  # 17:00 JST, not 17:30
        self.assertEqual(utc(access_deadline(s,timestamp('2026-10-31T01:00:00Z'))),'2026-10-31T03:00:00Z')  # 10:00 + 120 min
        s.config=dict(service_end_utc='2026-10-31T07:00:00Z',daily_service_hours=None)
        self.assertEqual(utc(access_deadline(s,now)),'2026-10-31T07:00:00Z')

import os
sys.path.insert(0,str(ROOT/'tests'))
from mysql_fixture import PreservedDirectory,init_home
MYSQL=bool(os.environ.get('WIFI_TEST_MYSQL_CONFIG'))

@unittest.skipUnless(MYSQL,'needs WIFI_TEST_MYSQL_CONFIG')
class Flow(unittest.TestCase):
    def setUp(self):
        self.temp=PreservedDirectory();self.home=Path(self.temp.name)/'data';init_home(self.home,sample=True)
        config=json.loads((self.home/'config.json').read_text(encoding='utf-8'))
        config.update(https_transport=HTTPS,vyos_portal=VYOS)
        (self.home/'config.json').write_text(json.dumps(config),encoding='utf-8');(self.home/'vyos-api.key').write_text(KEY+'\n',encoding='utf-8')
        self.clock=Clock();self.app=create_app(self.home,self.clock);self.s=self.app.extensions['service']
        self.s.network.background=False;self.router=FakeRouter();self.s.network.gateway.opener=self.router

    def call(self,client,method,path,ip,body=None,csrf='',key=None,origin=PORTAL):
        headers={'Origin':origin,'X-Forwarded-Proto':'https','X-Forwarded-For':ip,'X-CSRF-Token':csrf,'Idempotency-Key':key or uid()}
        return getattr(client,method)(path,base_url=origin,json=body if method=='post' else None,headers=headers,environ_overrides={'REMOTE_ADDR':'127.0.0.1'})

    def consent(self,ip,client=None):
        c=client or self.app.test_client()
        csrf=self.call(c,'post','/v1/session',ip,{}).json['csrf_token']
        r=self.call(c,'post','/v1/contexts',ip,{'launch_ref':None},csrf);self.assertEqual(r.status_code,201,r.json);context=r.json['context_id']
        t=self.call(c,'get','/v1/contexts/'+context+'?lang=ja',ip).json['terms']
        r=self.call(c,'post','/v1/consents',ip,dict(context_id=context,accepted=True,terms_document_id=t['document_id'],terms_sha256=t['sha256'],policy_version=t['policy_version'],language='ja'),csrf)
        self.assertEqual(r.status_code,201,r.json);self.assertEqual(r.json['display_state'],'connecting')
        return c,csrf,r.json

    def grant(self,c,ip,grant_id):return self.call(c,'get','/v1/grants/'+grant_id,ip).json

    def test_consent_connects_and_expiry_removes(self):
        ip='192.0.2.10';c,csrf,saved=self.consent(ip)
        self.assertEqual(self.call(c,'get','/capport/api',ip).json['captive'],True)
        self.assertEqual(process_due(self.s),1)
        self.assertEqual(self.router.members,{ip});g=self.grant(c,ip,saved['grant_id'])
        self.assertEqual((g['display_state'],g['network_verified'],g['adapter']),('connected',True,'vyos'))
        cap=self.call(c,'get','/capport/api',ip).json;self.assertEqual(cap['captive'],False);self.assertEqual(cap['seconds-remaining'],7200)
        self.assertTrue(self.call(c,'get','/capport/api','192.0.2.11').json['captive'])
        self.clock.value+=7200
        from jobs import housekeeping
        housekeeping(self.s)
        self.assertEqual(self.router.members,set())
        with self.s.db() as db:g=self.s.status(db.execute('SELECT * FROM grants WHERE id=?',(saved['grant_id'],)).fetchone())  # the visitor session has ended too
        self.assertEqual((g['display_state'],g['revocation_state'],g['network_verified']),('expired','confirmed',False))
        # The same device may consent again after its access ended.
        _,_,again=self.consent(ip,c);self.assertNotEqual(again['grant_id'],saved['grant_id']);process_due(self.s);self.assertEqual(self.router.members,{ip})

    def test_one_commit_for_many_consents(self):
        for n in range(5):self.consent('192.0.2.%d'%(20+n))
        self.assertEqual(process_due(self.s),5);self.assertEqual(len(self.router.commits),1);self.assertEqual(len(self.router.members),5)

    def test_address_checks(self):
        c=self.app.test_client();csrf=self.call(c,'post','/v1/session','198.51.100.7',{}).json['csrf_token']
        r=self.call(c,'post','/v1/contexts','198.51.100.7',{'launch_ref':None},csrf);self.assertEqual((r.status_code,r.json['code']),(403,'source_outside_guest'))
        c=self.app.test_client();csrf=self.call(c,'post','/v1/session','192.0.2.30',{}).json['csrf_token']
        context=self.call(c,'post','/v1/contexts','192.0.2.30',{'launch_ref':None},csrf).json['context_id']
        t=self.call(c,'get','/v1/contexts/'+context+'?lang=ja','192.0.2.30').json['terms']
        r=self.call(c,'post','/v1/consents','192.0.2.31',dict(context_id=context,accepted=True,terms_document_id=t['document_id'],terms_sha256=t['sha256'],policy_version=t['policy_version'],language='ja'),csrf)
        self.assertEqual((r.status_code,r.json['code']),(409,'source_changed'));self.assertEqual(process_due(self.s),0);self.assertEqual(self.router.commits,[])

    def test_router_down_retries_then_not_connected(self):
        ip='192.0.2.40';c,_,saved=self.consent(ip);self.router.fail=URLError('down')
        for _ in range(3):
            process_due(self.s);self.clock.value+=31
        g=self.grant(c,ip,saved['grant_id']);self.assertEqual((g['display_state'],g['authorization_status']),('rejected','rejected'))
        with self.s.db() as db:
            self.assertEqual(db.execute("SELECT state FROM notifications WHERE dedupe_key='portal_allow_failed'").fetchone()['state'],'open')
        self.router.fail=None;process_due(self.s);self.assertEqual(self.router.members,set())

    def test_revocation_keeps_address_shared_with_a_newer_grant(self):
        ip='192.0.2.50';first,_,old=self.consent(ip);second,_,new=self.consent(ip);process_due(self.s);self.assertEqual(self.router.members,{ip})
        admin=self.app.test_client()
        csrf=self.call(admin,'post','/v1/admin/session','192.0.2.99',{},origin=ADMIN).json['csrf_token']
        from manage import add_admin
        from werkzeug.security import generate_password_hash
        add_admin(self.s,'operator','operator',generate_password_hash('fixture-password',method='scrypt'))
        csrf=self.call(admin,'post','/v1/admin/login','192.0.2.99',dict(username='operator',password='fixture-password'),csrf,origin=ADMIN).json['csrf_token']
        r=self.call(admin,'post','/v1/admin/grants/'+old['grant_id']+'/revocations','192.0.2.99',dict(reason='operator_request'),csrf,origin=ADMIN);self.assertEqual(r.status_code,202)
        process_due(self.s);self.assertEqual(self.router.members,{ip})
        r=self.call(admin,'post','/v1/admin/grants/'+new['grant_id']+'/revocations','192.0.2.99',dict(reason='operator_request'),csrf,origin=ADMIN)
        process_due(self.s);self.assertEqual(self.router.members,set())
        overview=self.call(admin,'get','/v1/admin/overview','192.0.2.99',origin=ADMIN).json['counts']
        self.assertEqual((overview['network_authorized'],overview['network_failed']),(0,0))

if __name__=='__main__':unittest.main()
