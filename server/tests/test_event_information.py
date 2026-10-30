import unittest,json
import test_service as base
from app import Service,create_app,uid
from event_information import current,public,make_plan,apply_plan,normalize
from runtime_guard import owned_runtime

class InformationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):base.Tests.setUpClass.__func__(cls)
    setUp=base.Tests.setUp
    tearDown=base.Tests.tearDown
    post=base.Tests.post
    get=base.Tests.get
    login=base.Tests.login
    count=base.Tests.count
    def test_capport_api_keeps_every_client_captive(self):
        r=self.get('/capport/api')
        self.assertEqual(r.status_code,200);self.assertEqual(r.mimetype,'application/captive+json')
        self.assertEqual(r.json,{'captive':True,'user-portal-url':base.ORIGIN+'/'});self.assertEqual(r.headers['Cache-Control'],'no-store')
    def test_public_unknown_dates_hidden(self):
        info=self.get('/v1/public').json['event_information'];self.assertIsNone(info['ssid']);self.assertIsNone(info['service_start_utc'])
    def test_plan_only_and_idempotent(self):
        self.login();before=(self.home/'config.json').read_bytes();r=self.get('/v1/admin/event-information').json;key=uid()
        r['values']['name_ja']='試験の学校祭';data={k:r[k] for k in ('values','config_sha256')}
        first=self.post('/v1/admin/event-information/plans',data,key);self.assertEqual(first.status_code,201,first.json)
        again=self.post('/v1/admin/event-information/plans',data,key);self.assertEqual(first.json,again.json)
        self.assertEqual((self.home/'config.json').read_bytes(),before);self.assertEqual(len(list((self.home/'configuration-history').glob('event-info-plan-*'))),1)
    def test_apply_preserves_config_and_records(self):
        info=current(self.s.config);info.update(name_ja='学校祭テスト',ssid='test-only',period_confirmed=True)
        import hashlib
        plan=make_plan(self.s,info,hashlib.sha256((self.home/'config.json').read_bytes()).hexdigest());count=self.count('audit')
        result=apply_plan(self.s,plan);self.assertTrue(result['applied']);new=Service(self.home)
        self.assertEqual(public(new.config)['ssid'],'test-only');self.assertFalse(new.config['production_enabled']);self.assertGreater(self.count('audit'),count)
        self.assertEqual(len(list((self.home/'configuration-history').glob('*event-before.json'))),1)
        with self.assertRaises(ValueError):apply_plan(new,plan)
    def test_running_app_and_worker_refused(self):
        from event_information import config_hash
        plan=make_plan(self.s,current(self.s.config),config_hash(self.home))
        for name in ('app','worker'):
            with owned_runtime(self.home,name):
                with self.assertRaises(ValueError):apply_plan(self.s,plan)
    def test_config_changes_refused_during_incomplete_operation(self):
        import capacity_policy
        from event_information import config_hash
        original=(self.home/'config.json').read_bytes()
        plans=[(apply_plan,make_plan(self.s,current(self.s.config),config_hash(self.home))),(capacity_policy.apply_plan,capacity_policy.make_plan(self.s))]
        for marker in ('restore.incomplete','upgrade.incomplete','policy-apply.incomplete'):
            (self.home/marker).write_bytes(b'{}')
            try:
                for apply,plan in plans:
                    with self.assertRaisesRegex(ValueError,'Incomplete operation'):apply(self.s,plan)
            finally:(self.home/marker).unlink()
        self.assertEqual((self.home/'config.json').read_bytes(),original)
    def test_invalid_text_and_dates(self):
        data=current(self.s.config)
        for changes in ({'ssid':'あ'*11},{'name_ja':'bad\nline'},{'period_confirmed':1},{'service_end_utc':data['service_start_utc']},{'service_start_utc':None}):
            with self.assertRaises((ValueError,TypeError)):normalize({**data,**changes})
    def test_permissions(self):
        for role in ('viewer','operator','records'):
            self.login(role);self.assertEqual(self.get('/v1/admin/event-information').status_code,403)
            self.assertEqual(self.post('/v1/admin/event-information/plans',{}).status_code,403)
    def test_session_status_never_extends(self):
        self.login();first=self.get('/v1/admin/session-status').json;self.clock.value+=60
        second=self.get('/v1/admin/session-status').json;self.assertEqual(first['expires_at_utc'],second['expires_at_utc']);self.assertFalse(second['automatically_extended'])
        self.assertEqual(self.get('/v1/admin/overview').json['session_expires_at_utc'],first['expires_at_utc'])
        self.clock.value+=86400;self.assertEqual(self.get('/v1/admin/session-status').status_code,401)
if __name__=='__main__':unittest.main()
