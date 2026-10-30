"""VyOS gateway against a fake router; no network, no MySQL."""
import sys,io,json,socket,ssl,unittest
from pathlib import Path
from urllib.error import HTTPError,URLError
from urllib.parse import parse_qs
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from vyos_gateway import VyosGateway,GatewayRefused,GatewayRejected,GatewayUnavailable,BASE

KEY='fixture-only-not-a-real-key'
NETS=['192.0.2.0/24']

class Answer(io.BytesIO):
    def __enter__(self):return self
    def __exit__(self,*a):self.close()

class FakeRouter:
    """Keeps the group like VyOS: set is idempotent, delete of a missing address fails."""
    def __init__(self,members=()):self.members=set(members);self.requests=[];self.fail=None
    def __call__(self,request,timeout,context):
        self.requests.append(dict(url=request.full_url,timeout=timeout,context=context,form=parse_qs(request.data.decode())))
        if self.fail:raise self.fail
        form=parse_qs(request.data.decode());data=json.loads(form['data'][0])
        if form['key'][0]!=KEY:raise HTTPError(request.full_url,403,'Forbidden',{},io.BytesIO(b''))
        path=data['path']
        if request.full_url.endswith('/retrieve'):
            if not self.members:return self.answer(False,error='Configuration under specified path is empty')
            listed=sorted(self.members);return self.answer(True,{'address':listed[0] if len(listed)==1 else listed})
        if data['op']=='set':self.members.add(path[-1]);return self.answer(True)
        if path[-1] not in self.members:return self.answer(False,error='Nothing to delete')
        self.members.discard(path[-1]);return self.answer(True)
    def answer(self,success,data=None,error=None):return Answer(json.dumps({'success':success,'data':data,'error':error}).encode())

def gateway(router,**extra):return VyosGateway('https://core-rt.example.test',extra.pop('key',KEY),NETS,opener=router,**extra)

class VyosGatewayTests(unittest.TestCase):
    def test_allow_list_revoke(self):
        router=FakeRouter();g=gateway(router)
        self.assertEqual(g.authorized(),[])
        self.assertEqual(g.allow('192.0.2.10'),'192.0.2.10')
        self.assertEqual(g.authorized(),['192.0.2.10'])
        g.allow('192.0.2.11');self.assertEqual(g.authorized(),['192.0.2.10','192.0.2.11'])
        self.assertTrue(g.revoke('192.0.2.10'));self.assertEqual(router.members,{'192.0.2.11'})

    def test_duplicate_allow_and_missing_revoke(self):
        router=FakeRouter();g=gateway(router)
        g.allow('192.0.2.10');g.allow('192.0.2.10')
        self.assertEqual(router.members,{'192.0.2.10'})
        self.assertFalse(g.revoke('192.0.2.99'))
        self.assertFalse(any(json.loads(r['form']['data'][0])['op']=='delete' for r in router.requests))

    def test_every_request_stays_in_the_group(self):
        router=FakeRouter();g=gateway(router)
        g.allow('192.0.2.10');g.authorized();g.revoke('192.0.2.10')
        for r in router.requests:
            self.assertEqual(json.loads(r['form']['data'][0])['path'][:4],BASE)
            self.assertEqual(r['form']['key'],[KEY])
            self.assertTrue(r['url'].startswith('https://core-rt.example.test/'))

    def test_addresses_outside_guest_networks_refused_without_contact(self):
        router=FakeRouter();g=gateway(router)
        for bad in ('198.51.100.11','192.0.3.1','192.0.2.0/24','2001:db8::1','192.0.2.1 ','',None,'192.0.2.1/32'):
            with self.assertRaises(GatewayRefused):g.allow(bad)
        self.assertEqual(router.requests,[])

    def test_settings_refused(self):
        for origin in ('http://core-rt.example.test','https://core-rt.example.test/api','https://u:p@core-rt.example.test','https://core-rt.example.test?x=1','',None):
            with self.assertRaises(GatewayRefused):VyosGateway(origin,KEY,NETS)
        for args in ((KEY,[]),('',NETS),(KEY,['not-a-net']),(KEY,['2001:db8::/32'])):
            with self.assertRaises(GatewayRefused):VyosGateway('https://core-rt.example.test',*args)
        for timeout in (0,31,'5',True):
            with self.assertRaises(GatewayRefused):VyosGateway('https://core-rt.example.test',KEY,NETS,timeout=timeout)
        for timeout in (0,31,'20',True):
            with self.assertRaises(GatewayRefused):VyosGateway('https://core-rt.example.test',KEY,NETS,commit_timeout=timeout)

    def test_certificate_verification_on(self):
        router=FakeRouter();gateway(router,timeout=3).authorized()
        context=router.requests[0]['context']
        self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED);self.assertTrue(context.check_hostname)
        self.assertEqual(router.requests[0]['timeout'],3)

    def test_failures_are_typed(self):
        g=gateway(FakeRouter(),key='wrong-key')
        with self.assertRaisesRegex(GatewayRejected,'key refused'):g.allow('192.0.2.10')
        router=FakeRouter();g=gateway(router)
        for error in (socket.timeout('timed out'),TimeoutError(),URLError('refused'),ssl.SSLCertVerificationError('bad cert')):
            router.fail=error
            with self.assertRaises(GatewayUnavailable):g.allow('192.0.2.10')
        router.fail=HTTPError('u',500,'err',{},io.BytesIO(b''))
        with self.assertRaisesRegex(GatewayUnavailable,'500'):g.allow('192.0.2.10')
        router.fail=HTTPError('u',400,'bad',{},io.BytesIO(b'{"success":false,"error":"Invalid path","data":null}'))
        with self.assertRaisesRegex(GatewayRejected,'Invalid path'):g.allow('192.0.2.10')

    def test_unusable_answers(self):
        for raw in (b'not json',b'[1]',b'x'*1048577):
            g=gateway(lambda request,timeout,context,raw=raw:Answer(raw))
            with self.assertRaises(GatewayUnavailable):g.allow('192.0.2.10')
        g=gateway(lambda request,timeout,context:Answer(b'{"success":true,"data":{"address":5}}'))
        with self.assertRaises(GatewayUnavailable):g.authorized()

    def test_errors_do_not_carry_the_key(self):
        router=FakeRouter();router.fail=URLError(KEY);g=gateway(router)
        try:g.allow('192.0.2.10')
        except GatewayUnavailable as error:
            self.assertNotIn(KEY,str(error));self.assertIsNone(error.__cause__)

if __name__=='__main__':unittest.main()
