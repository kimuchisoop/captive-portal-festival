"""Measure real consent writes plus batched VyOS operation latency against a fake delayed gateway.

Run on Windows after preparing the disposable MySQL 8.4 fixture:
  python tests/vyos_load_check.py 300 10 0.5
Arguments are visitors, arrival window seconds, and simulated VyOS configure-commit seconds.
No real router is contacted. Test records are retained in the fixture directory.
"""
import concurrent.futures,ipaddress,json,statistics,sys,threading,time
from pathlib import Path
from urllib.parse import parse_qs

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from test_network_access import Flow
from network_access import BATCH,BATCH_WINDOW,process_due

def percentile(values,p):
    ordered=sorted(values)
    return ordered[min(len(ordered)-1,round((len(ordered)-1)*p))]

def main(visitors,duration,commit_seconds):
    if visitors<1 or duration<=0 or commit_seconds<0:raise SystemExit('visitors must be positive; seconds cannot be negative')
    flow=Flow(methodName='test_one_commit_for_many_consents');flow.setUp()
    # Exercise the integration pipeline above the provisional per-minute session cap in this process only.
    flow.s.session_guard.bootstrap._source_limit=flow.s.session_guard.bootstrap._global_limit=max(1000,visitors*2)
    flow.s.session_guard.issue._source_limit=flow.s.session_guard.issue._global_limit=max(1000,visitors*2)
    # Use a private test-only /22 so every simulated visitor has a unique address.
    test_network=ipaddress.IPv4Network('10.254.0.0/22')
    first=ipaddress.IPv4Address('10.254.0.1')
    addresses=[str(first+i) for i in range(visitors)]
    if any(ipaddress.IPv4Address(ip) not in test_network for ip in addresses):
        raise SystemExit('visitors exceed the test-only /22 address range')
    flow.s.network.settings['guest_networks']=[test_network]
    flow.s.network.gateway.networks=[test_network]
    router=flow.router;calls=[];original=router.__call__
    def delayed(request,timeout,context):
        if request.full_url.endswith('/configure'):
            started=time.monotonic();time.sleep(commit_seconds)
            calls.append(dict(start=started,seconds=time.monotonic()-started,timeout=timeout,commands=len(json.loads(parse_qs(request.data.decode())['data'][0]))))
        return original(request,timeout,context)
    flow.s.network.gateway.opener=delayed
    stop=threading.Event();wake=threading.Event();observer_stop=threading.Event()
    accepted_at={};saved=[];saved_lock=threading.Lock();errors=[]
    def dispatcher():
        while not stop.is_set():
            wake.wait(BATCH_WINDOW)
            if stop.is_set():break
            wake.clear()
            try:flow.s.network.background=False;process_due(flow.s)
            except Exception as e:errors.append(dict(type=type(e).__name__,message=str(e)[:160]))
    thread=threading.Thread(target=dispatcher,name='vyos-load-dispatch',daemon=True);thread.start()
    start=time.monotonic();workers=min(64,visitors)
    def visitor(i):
        due=start+(i*duration/visitors)
        delay=due-time.monotonic()
        if delay>0:time.sleep(delay)
        try:
            _,_,receipt=flow.consent(addresses[i])
            with saved_lock:saved.append(dict(grant_id=receipt['grant_id'],at=time.monotonic()))
            wake.set()
        except Exception as error:errors.append(dict(type=type(error).__name__,message=str(error)[:160]))

    def observe_authorizations():
        while not observer_stop.is_set():
            try:
                with flow.s.db() as db:
                    rows=db.execute("SELECT id,authorization_status FROM grants WHERE authorization_status IN ('accepted','rejected')").fetchall()
                observed=time.monotonic()
                with saved_lock:
                    known={item['grant_id'] for item in saved}
                for row in rows:
                    if row['id'] not in known:continue
                    if row['authorization_status']=='accepted':accepted_at.setdefault(row['id'],observed)
                    elif not any(error.get('type')=='authorization_rejected' for error in errors):
                        errors.append(dict(type='authorization_rejected',count=sum(r['authorization_status']=='rejected' for r in rows)))
            except Exception as error:
                errors.append(dict(type=type(error).__name__,message=str(error)[:160]))
                return
            observer_stop.wait(0.25)

    observer=threading.Thread(target=observe_authorizations,name='vyos-load-observer',daemon=True);observer.start()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures=[pool.submit(visitor,i) for i in range(visitors)]
        for f in futures:f.result()
    deadline=time.monotonic()+max(180,commit_seconds*((visitors+BATCH-1)//BATCH+2)+10)
    while time.monotonic()<deadline and len(accepted_at)<visitors and not errors:time.sleep(0.1)
    observer_stop.set();observer.join(timeout=2)
    stop.set();wake.set();thread.join(timeout=max(5,commit_seconds+2))
    with saved_lock:saved_snapshot=list(saved)
    wait=[(accepted_at[x['grant_id']]-x['at'])*1000 for x in saved_snapshot if x['grant_id'] in accepted_at]
    allow=dict(requested=visitors,consent_saved=len(saved),authorized=len(wait),errors=errors,
               unique_ip_count=len(set(addresses)),authorization_observation_interval_ms=250,
               elapsed_seconds=round(time.monotonic()-start,2),commit_count=len(calls),batch_sizes=[x['commands'] for x in calls],
               commit_timeout_seconds=flow.s.network.gateway.commit_timeout,
               session_caps='temporarily raised in this test process only',commit_seconds=commit_seconds,
               authorization_wait_ms=dict(p50=round(statistics.median(wait),1),p95=round(percentile(wait,.95),1),max=round(max(wait),1)) if wait else None)
    if len(wait)!=visitors:raise SystemExit(json.dumps(allow,ensure_ascii=False))
    # Measure expiry scheduling, database updates, router reads, and commits together.
    flow.clock.value+=7200
    from jobs import housekeeping
    t=time.monotonic()
    housekeeping(flow.s)
    revoke_seconds=time.monotonic()-t
    allow['bulk_revoke']=dict(seconds=round(revoke_seconds,2),commit_count=len(calls)-allow['commit_count'],members_remaining=len(router.members))
    result_path=Path(flow.temp.name)/('vyos-load-'+str(visitors)+'-'+str(round(commit_seconds*1000))+'ms.json')
    result_path.write_text(json.dumps(allow,ensure_ascii=False,indent=2),encoding='utf-8')
    allow['result_file']=str(result_path)
    print(json.dumps(allow,ensure_ascii=False,indent=2))
    flow.doCleanups()
    expected_revoke_commits=(len(set(addresses))+BATCH-1)//BATCH
    if router.members or allow['bulk_revoke']['commit_count']!=expected_revoke_commits:
        raise SystemExit('mass revoke verification failed')

if __name__=='__main__':
    if len(sys.argv)!=4:raise SystemExit('usage: python tests/vyos_load_check.py <visitors> <seconds> <commit_seconds>')
    main(int(sys.argv[1]),float(sys.argv[2]),float(sys.argv[3]))
