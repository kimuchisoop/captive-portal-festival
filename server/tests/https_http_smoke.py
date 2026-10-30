"""Real loopback Waitress requests with proxy headers, not an actual TLS/certificate test."""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import http.client,json,secrets,socket,subprocess,time
from mysql_fixture import new_database,PreservedDirectory
from manage import initialize,add_admin
from werkzeug.security import generate_password_hash

checks=[]
def check(name,condition):
    if not condition: raise AssertionError(name)
    checks.append(name)
temp=PreservedDirectory();home=Path(temp.name)/'https-http'
with socket.socket() as sock: sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
s=initialize(home,db_settings=new_database());password=secrets.token_urlsafe(24)
add_admin(s,'httpsqa','settings',generate_password_hash(password))
c=s.config;c['origin']='http://127.0.0.1:'+str(port);c['https_transport']=dict(enabled=True,portal_origin='https://wifi.example.org',admin_origin='https://admin.example.org',trusted_proxy='127.0.0.1')
(home/'config.json').write_text(json.dumps(c),encoding='utf-8')
log=(Path(temp.name)/'https-http.log').open('xb');process=subprocess.Popen([sys.executable,str(ROOT/'manage.py'),'--home',str(home),'serve'],stdout=log,stderr=log,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
cookie=''
def call(path,method='GET',data=None,host='admin.example.org',origin='https://admin.example.org',extra=None,proxy=True):
    connection=http.client.HTTPConnection('127.0.0.1',port,timeout=10)
    headers={'Host':host,'Content-Type':'application/json','Origin':origin,'Cookie':cookie}
    if proxy: headers.update({'X-Forwarded-Proto':'https','X-Forwarded-For':'192.0.2.1'})
    headers.update(extra or {})
    connection.request(method,path,json.dumps(data) if data is not None else None,headers);r=connection.getresponse();payload=r.read();h=dict(r.getheaders());status=r.status;connection.close()
    try: payload=json.loads(payload)
    except ValueError: payload={}
    return status,h,payload
try:
    for attempt in range(100):
        try: call('/admin');break
        except OSError: time.sleep(.1)
    status,headers,_=call('/admin');check('exact proxy headers survive Waitress and reach admin',status==200)
    check('HTTPS security header is returned',headers.get('Strict-Transport-Security')=='max-age=3600')
    check('direct request without proxy headers is refused',call('/admin',proxy=False)[0]==400)
    check('public hostname cannot reach admin',call('/admin',host='wifi.example.org')[0]==400)
    check('forwarded host spoofing refused',call('/admin',extra={'X-Forwarded-Host':'evil.example.org'})[0]==400)
    check('multiple forwarded client addresses refused',call('/admin',extra={'X-Forwarded-For':'192.0.2.1, 10.0.0.1'})[0]==400)
    check('cross-origin state change refused',call('/v1/admin/session','POST',{},origin='https://wifi.example.org')[0]==403)
    status,headers,data=call('/v1/admin/session','POST',{});check('session bootstrap succeeds',status==200)
    check('session cookie Secure HttpOnly SameSite and host-only','Secure;' in headers['Set-Cookie'] and 'HttpOnly;' in headers['Set-Cookie'] and 'SameSite=Strict' in headers['Set-Cookie'] and 'Domain=' not in headers['Set-Cookie'])
    cookie=headers['Set-Cookie'].split(';',1)[0]
    status,headers,data=call('/v1/admin/login','POST',dict(username='httpsqa',password=password),extra={'X-CSRF-Token':data['csrf_token']});check('admin login succeeds with CSRF',status==200 and data['authenticated'])
    cookie=headers['Set-Cookie'].split(';',1)[0];csrf=data['csrf_token']
    check('authenticated admin summary succeeds',call('/v1/admin/overview')[0]==200)
    status,headers,data=call('/v1/public',host='wifi.example.org',origin='https://wifi.example.org');check('portal intake and production stay disabled',status==200 and data['service_state']=='intake_disabled' and not data['production_enabled'])
    status,headers,data=call('/v1/admin/logout','POST',{},extra={'X-CSRF-Token':csrf});check('logout cookie remains Secure',status==200 and 'Secure;' in headers['Set-Cookie'])
    check('old session invalidated after logout',call('/v1/admin/overview')[0]==401)
    print(json.dumps(dict(passed=len(checks),failed=0,checks=checks,actual_tls_test=False,logs_retained=True),ensure_ascii=False))
finally:
    process.terminate();process.wait(timeout=15);log.close()
