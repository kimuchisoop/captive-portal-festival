"""Local load check: raw throughput of the visitor consent flow against a disposable MySQL.

Usage: WIFI_TEST_MYSQL_CONFIG=<test config> python tests/load_check.py [visitors] [concurrency]

The server runs as in production (waitress, 4 threads) in a separate process. The session
admission limits in session_guard.py are lifted inside that process only, so the numbers show
what the application and MySQL can process, not what the admission limits allow. Launch links
are minted directly in the database here; on site they would come from the AP integration.
"""
import http.cookiejar,json,os,socket,statistics,subprocess,sys,threading,time,urllib.error,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from mysql_fixture import PreservedDirectory,init_home
from app import Service,uid
from manage import mint_launch

SERVER='''import sys;sys.path.insert(0,{root!r})
import session_guard as g
g.BOOTSTRAP_SOURCE_LIMIT=g.BOOTSTRAP_GLOBAL_LIMIT=g.ISSUE_SOURCE_LIMIT=g.ISSUE_GLOBAL_LIMIT=10**9
sys.argv=['manage.py','--home',{home!r},'serve']
import manage;manage.main()
'''

def main(visitors=600,concurrency=32):
    home=Path(PreservedDirectory().name)/'load-data';init_home(home,sample=True)
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    origin='http://127.0.0.1:'+str(port)
    config=json.loads((home/'config.json').read_text(encoding='utf-8'));config['origin']=origin
    (home/'config.json').write_text(json.dumps(config),encoding='utf-8')
    s=Service(home)
    process=subprocess.Popen([sys.executable,'-c',SERVER.format(root=str(ROOT),home=str(home))],
                             stdout=(home/'load-stdout.log').open('xb'),stderr=(home/'load-stderr.log').open('xb'),
                             creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    timings={};errors={};lock=threading.Lock()
    def record(name,started,status):
        with lock:
            timings.setdefault(name,[]).append(time.perf_counter()-started)
            if status>=400:errors[name+' '+str(status)]=errors.get(name+' '+str(status),0)+1
    def visitor():
        opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        def req(name,path,data=None,csrf=None):
            headers={'Content-Type':'application/json','Origin':origin}
            if csrf:headers['X-CSRF-Token']=csrf
            if data is not None:headers['Idempotency-Key']=uid()
            started=time.perf_counter()
            try:r=opener.open(urllib.request.Request(origin+path,data=json.dumps(data).encode() if data is not None else None,headers=headers),timeout=30)
            except urllib.error.HTTPError as e:r=e
            body=r.read();record(name,started,r.status)
            return r.status,json.loads(body) if r.headers.get_content_type()=='application/json' else None
        req('public','/v1/public?lang=ja')
        status,session=req('session','/v1/session',{})
        if status!=200:return
        csrf=session['csrf_token']
        started=time.perf_counter();launch=mint_launch(s).split('=',1)[1];record('launch(mint, AP side)',started,200)
        status,context=req('context','/v1/contexts',{'launch_ref':launch},csrf)
        if status!=201:return
        status,context=req('context_read','/v1/contexts/'+context['context_id']+'?lang=ja')
        terms=context['terms']
        req('consent','/v1/consents',dict(context_id=context['context_id'],accepted=True,terms_document_id=terms['document_id'],
            terms_sha256=terms['sha256'],policy_version=terms['policy_version'],language='ja'),csrf)
    try:
        for _ in range(200):
            if process.poll() is not None:raise RuntimeError('server exited; see '+str(home/'load-stderr.log'))
            try:
                if urllib.request.urlopen(origin+'/health/live',timeout=2).status==200:break
            except OSError:time.sleep(.1)
        else:raise TimeoutError('server not ready')
        queue=list(range(visitors));queue_lock=threading.Lock()
        def worker():
            while True:
                with queue_lock:
                    if not queue:return
                    queue.pop()
                try:visitor()
                except Exception as e:
                    with lock:errors[type(e).__name__]=errors.get(type(e).__name__,0)+1
        started=time.perf_counter()
        threads=[threading.Thread(target=worker) for _ in range(concurrency)]
        for t in threads:t.start()
        for t in threads:t.join()
        elapsed=time.perf_counter()-started
    finally:
        process.terminate();process.wait(30)
    consents=len([1 for _ in timings.get('consent',[])])-sum(v for k,v in errors.items() if k.startswith('consent '))
    report=dict(visitors=visitors,concurrency=concurrency,elapsed_seconds=round(elapsed,1),
                completed_consents=consents,consents_per_minute=round(consents/elapsed*60),errors=errors,
                latency_ms={name:dict(count=len(v),p50=round(statistics.median(v)*1000),p95=round(sorted(v)[int(len(v)*.95)-1]*1000),
                                      max=round(max(v)*1000)) for name,v in timings.items()},data=str(home))
    print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=='__main__':main(*(int(v) for v in sys.argv[1:3]))
