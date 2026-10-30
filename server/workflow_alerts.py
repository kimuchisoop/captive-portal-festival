"""Six fixed public summaries, with private details filtered on every request."""
import hashlib,heapq,json
from flask import g,jsonify,request
from app import uid,utc
from workflow_common import canonical,sha,read_private,query,encode_cursor,decode_cursor,fail,policy
from workflow_generation import require_runtime_ready,runtime_observations
from jobs import set_meta
import event_info_repository as plans

TOPICS={
 'plan_review_pending':('info','変更案の確認待ちがあります。設定担当は変更案一覧を確認してください。'),
 'plan_review_required':('warning','変更案の再確認が必要です。設定担当は変更案一覧を確認してください。'),
 'plan_apply_unknown':('critical','設定の適用結果を確認できません。サーバー担当へ照合を依頼してください。'),
 'plan_activation_pending':('warning','設定の反映を確認できません。設定担当は反映状況を確認してください。'),
 'archive_export_failed':('warning','記録出力の準備に確認が必要です。依頼した担当者は自分の出力一覧を確認してください。'),
 'schema5_recovery_required':('critical','復旧後の確認が必要です。サーバー担当へ連絡してください。'),
}

def detail(code,kind,resource_id,created,state,plan_id=None,owner=None,version=None):
    severity,message=TOPICS[code]
    return dict(alert_id=code+':'+resource_id,code=code,severity=severity,resource_kind=kind,resource_id=resource_id,plan_id=plan_id,
                first_seen_at_utc=utc(created),message=message,action='open_own_export' if kind=='archive_export' else 'open_application_status' if kind=='apply_attempt' else 'open_plan' if kind=='event_plan' else 'contact_server_operator',
                effective_state=state,_owner=owner,_created=created,_version=version)

def conditions(s,db):
    configured=policy(s);generation=require_runtime_ready(s,db);config=read_private(s.home,'.','config.json');current_sha=sha(config);runtime=runtime_observations(s,db)
    last=''
    while True:
        rows=db.execute(plans.PLAN_SELECT+"WHERE p.id>? AND e.state_after IN ('review_pending','reviewed') AND NOT EXISTS (SELECT 1 FROM event_info_apply_attempts a JOIN event_info_apply_observations o ON o.attempt_id=a.id AND o.observation_version=(SELECT MAX(v.observation_version) FROM event_info_apply_observations v WHERE v.attempt_id=a.id) WHERE a.plan_id=p.id AND o.outcome='file_written') ORDER BY p.id LIMIT 100",(last,)).fetchall()
        if not rows:break
        for row in rows:
            value=plans.view(s,db,row,False,config,generation)
            if row['state_after']=='review_pending':yield detail('plan_review_pending','event_plan',row['id'],row['event_time'],'review_pending',row['id'],version=row['plan_version'])
            elif value['effective_state']=='review_required':yield detail('plan_review_required','event_plan',row['id'],row['event_time'],'review_required',row['id'],version=row['plan_version'])
        last=rows[-1]['id']
    last=''
    known=db.execute('SELECT plan_id FROM event_info_apply_attempts WHERE expected_after_config_sha256=? ORDER BY created_at DESC,id DESC LIMIT 1',(current_sha,)).fetchone()
    while True:
        rows=db.execute('SELECT a.*,o.outcome,o.observation_version FROM event_info_apply_attempts a LEFT JOIN event_info_apply_observations o ON o.attempt_id=a.id AND o.observation_version=(SELECT MAX(v.observation_version) FROM event_info_apply_observations v WHERE v.attempt_id=a.id) WHERE a.id>? ORDER BY a.id LIMIT 100',(last,)).fetchall()
        if not rows:break
        for row in rows:
            if row['outcome'] in ('unknown','conflict') or row['outcome'] is None and s.now()-row['created_at']>=configured['stale_after_seconds']:
                yield detail('plan_apply_unknown','apply_attempt',row['id'],row['created_at'],'unknown',row['plan_id'],version=row['observation_version'])
            elif row['outcome']=='file_written' and s.now()-row['created_at']>=configured['activation_grace_seconds']:
                if known and known['plan_id']!=row['plan_id']:continue
                matched=all(value['state']=='active' and value['config_sha256']==row['expected_after_config_sha256'] for value in runtime.values())
                if not matched:yield detail('plan_activation_pending','apply_attempt',row['id'],row['created_at'],'restart_required',row['plan_id'],version=row['observation_version'])
        last=rows[-1]['id']
    # Retain only the small dependency graph, never consent rows or CSV contents.
    jobs={r['id']:dict(r) for r in db.execute('SELECT id,owner_id,state,filters_sha256,retry_of_id,created_at,row_version FROM consent_archive_exports ORDER BY id').fetchall()}
    children={key:[] for key in jobs}
    for job in jobs.values():
        if job['retry_of_id'] in children:children[job['retry_of_id']].append(job['id'])
    roots={};invalid=set()
    for identifier,job in jobs.items():
        if identifier in roots:continue
        node=identifier;path=[];seen=set();valid=True
        while node not in roots:
            if node in seen:root=min(seen);valid=False;break
            seen.add(node);path.append(node);parent=jobs[node]['retry_of_id']
            if not parent:root=node;break
            if parent not in jobs or (jobs[parent]['owner_id'],jobs[parent]['filters_sha256'])!=(job['owner_id'],job['filters_sha256']):root=node;valid=False;break
            node=parent
        else:root=roots[node]
        for member in path:roots[member]=root
        if not valid:invalid.add(root)
    groups={}
    for member,root in roots.items():groups.setdefault(root,[]).append(member)
    for root,members in sorted(groups.items()):
        valid=root not in invalid;node=root;visited=set();resolved=False;has_issue=not valid
        while valid:
            if node in visited:has_issue=True;break
            visited.add(node);entry=jobs[node];branches=children[node]
            if len(branches)>1:has_issue=True;break
            if entry['state']=='failed':has_issue=True
            if not branches:
                if entry['state']=='ready':
                    import archive_repository as archives
                    complete=archives.load(db,entry['owner_id'],entry['id']);snapshot=db.execute('SELECT * FROM consent_archive_snapshots WHERE export_id=?',(entry['id'],)).fetchone()
                    resolved=archives.ready_evidence(s,db,complete,snapshot)
                    if not resolved:has_issue=True
                elif entry['state'] in ('queued','preparing'):
                    import archive_repository as archives
                    if not archives.current_generation(s,db,entry):has_issue=True
                break
            if (jobs[branches[0]]['owner_id'],jobs[branches[0]]['filters_sha256'])!=(entry['owner_id'],entry['filters_sha256']):has_issue=True;break
            node=branches[0]
        if has_issue and not resolved:
            version=sha(canonical([[member,jobs[member]['state'],jobs[member]['row_version'],jobs[member]['retry_of_id']] for member in sorted(members)]))
            entry=jobs[root];yield detail('archive_export_failed','archive_export',root,entry['created_at'],'recovery_required' if not valid else entry['state'],owner=entry['owner_id'],version=version)

def monitor(s):
    # A single write lock binds source predicates, fingerprints and public transitions.
    with s.db(True) as db:
        hashes={code:hashlib.sha256() for code in TOPICS};counts={code:0 for code in TOPICS}
        for item in conditions(s,db):
            # Time-of-day and heartbeat seen_at are deliberately absent.
            hashes[item['code']].update(canonical({key:item[key] for key in ('resource_kind','resource_id','plan_id','effective_state','_version')})+b'\n');counts[item['code']]+=1
        now=s.now()
        for code,(severity,message) in TOPICS.items():
            old=db.execute('SELECT * FROM notifications WHERE dedupe_key=?',(code,)).fetchone()
            previous=db.execute('SELECT value FROM meta WHERE name=?',('workflow5_'+code,)).fetchone()
            fingerprint=hashes[code].hexdigest()
            if not counts[code]:
                if old and old['state']!='resolved':
                    db.execute("UPDATE notifications SET state='resolved',last_seen=? WHERE id=?",(now,old['id']));s.audit(db,'worker','workflow_notification_resolved',old['id']+':'+str(old['generation']))
            elif not old:
                notification_id=uid()
                db.execute("INSERT INTO notifications (id,dedupe_key,severity,code,message,state,first_seen,last_seen,generation) VALUES (?,?,?,?,?,'open',?,?,1)",(notification_id,code,severity,code,message,now,now))
                s.audit(db,'worker','workflow_notification_opened',notification_id+':1')
            elif old['state']=='resolved' or not previous or previous['value']!=fingerprint:
                db.execute("UPDATE notifications SET state='open',first_seen=?,last_seen=?,generation=generation+1,acknowledged_by=NULL,acknowledged_at=NULL WHERE id=?",(now,now,old['id']))
                s.audit(db,'worker','workflow_notification_generation_changed',old['id']+':'+str(old['generation']+1))
            else:db.execute('UPDATE notifications SET last_seen=? WHERE id=?',(now,old['id']))
            set_meta(db,'workflow5_'+code,fingerprint)

def register(app,s,auth):
    @app.get('/v1/admin/workflow-alerts')
    @auth('admin','read')
    def alerts():
        args=query(request.args,('cursor','limit'));owner=g.session['owner_id'];role=g.session['admin']['role']
        from workflow_routes import limit_value
        limit=limit_value(args);position=None;expires=None
        if args.get('cursor'):position,expires=decode_cursor(s,args['cursor'],'workflow-alerts',owner,role)
        with s.db() as db:
            rows=db.execute("SELECT * FROM notifications WHERE code IN ("+','.join('?' for _ in TOPICS)+") AND state!='resolved' ORDER BY code",list(TOPICS)).fetchall()
            summary=[dict(notification_id=r['id'],code=r['code'],severity=r['severity'],state=r['state'],generation=r['generation'],message=TOPICS[r['code']][1]) for r in rows]
            def visible():
                if role not in ('records','settings'):return
                for item in conditions(s,db):
                    if item['resource_kind']=='archive_export':
                        if item['_owner']!=owner:continue
                    elif role!='settings':continue
                    order=[item['_created'],item['alert_id']]
                    if position is None or order<position:yield item
            selected=heapq.nlargest(limit+1,visible(),key=lambda item:(item['_created'],item['alert_id']))
            cursor=encode_cursor(s,'workflow-alerts',owner,[selected[limit-1]['_created'],selected[limit-1]['alert_id']],role,expires) if len(selected)>limit else None
        return jsonify(summary=summary,items=[{k:v for k,v in item.items() if not k.startswith('_')} for item in selected[:limit]],next_cursor=cursor,observed_at_utc=utc(s.now()),complete_snapshot=False)
