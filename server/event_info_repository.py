"""Append-only plans, independent review and stopped, observable application."""
import json,os
from app import Service,uid,utc
from event_information import normalize,current,make_plan
from workflow_common import canonical,sha,target,read_private,private_dir,strict_json,fail,policy,identifier
from workflow_generation import require_runtime_ready,runtime_observations
from jobs import secure_new_file

PLAN_SELECT=('SELECT p.*,e.id AS event_id,e.plan_version,e.kind,e.state_after,e.actor_id,e.created_at AS event_time,'
 'e.confirmed_content_sha256,e.review_valid_until,e.reason_code,a.enabled AS actor_enabled,a.role AS actor_role,'
 'c.reason_code AS created_reason,c.note AS created_note '
 'FROM event_info_plans p JOIN event_info_plan_events e ON e.plan_id=p.id '
 'AND e.plan_version=(SELECT MAX(v.plan_version) FROM event_info_plan_events v WHERE v.plan_id=p.id) '
 'LEFT JOIN admins a ON a.id=e.actor_id LEFT JOIN event_info_plan_events c ON c.plan_id=p.id AND c.plan_version=1 ')

def settings_actor(db,actor):
    row=db.execute('SELECT role,enabled FROM admins WHERE id=?',(actor,)).fetchone()
    if not row or not row['enabled'] or row['role']!='settings':fail('permission_denied',403)

def load(db,plan_id):
    row=db.execute(PLAN_SELECT+'WHERE p.id=?',(identifier(plan_id),)).fetchone()
    if not row:fail('plan_not_found',404)
    return row

def event(s,db,row,kind,state,actor,note=None,reason=None,review_until=None):
    event_id=uid();version=row['plan_version']+1
    db.execute('INSERT INTO event_info_plan_events (id,plan_id,plan_version,kind,state_after,actor_id,created_at,confirmed_content_sha256,review_valid_until,reason_code,note) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
               (event_id,row['id'],version,kind,state,actor,s.now(),row['content_sha256'] if kind=='review_recorded' else None,review_until,reason,note))
    s.audit(db,actor,'event_plan_'+kind,row['id'])
    return event_id

def saved(s,db,actor,values,base_sha,import_note=None):
    settings_actor(db,actor);require_runtime_ready(s,db)
    plan=make_plan(s,values,base_sha)
    raw_config=read_private(s.home,'.','config.json')
    if sha(raw_config)!=base_sha:fail('config_changed')
    baseline=current(strict_json(raw_config));plan_id=uid();filename='event-info-plan-'+plan_id+'.json';raw=canonical(plan)
    directory=private_dir(s.home,'configuration-history');secure_new_file(directory/filename,raw)
    # Check again after the filesystem work. A failed TX leaves its source as evidence.
    if read_private(s.home,'.','config.json')!=raw_config:fail('config_changed')
    db.execute('INSERT INTO event_info_plans (id,created_by,created_at,target_hash,base_config_sha256,content_sha256,base_values_json,values_json,source_file_sha256,source_file) VALUES (?,?,?,?,?,?,?,?,?,?)',
               (plan_id,actor,plan['created_at'],target(s.home),base_sha,sha(canonical(plan['values'])),canonical(baseline).decode(),canonical(plan['values']).decode(),sha(raw),filename))
    db.execute('INSERT INTO event_info_plan_events (id,plan_id,plan_version,kind,state_after,actor_id,created_at,confirmed_content_sha256,review_valid_until,reason_code,note) VALUES (?,?,1,?,?,?, ?,NULL,NULL,?,?)',
               (uid(),plan_id,'created','saved',actor,s.now(),'legacy_import' if import_note else None,import_note))
    s.audit(db,actor,'event_information_plan_saved',plan_id)
    return dict(plan_id=plan_id,filename=filename,values=plan['values'],applied=False,scope='local_display_only')

def provenance(s,row,verify):
    if row['created_reason']!='legacy_import':return None
    parts=(row['created_note'] or '').split('|')
    if len(parts)!=5 or parts[0]!='legacy-import':raise ValueError('Invalid import provenance')
    result=dict(source_sha256=parts[1],source_plan_id=identifier(parts[2]),report_id=identifier(parts[3]),report_sha256=parts[4],status='not_checked')
    if verify:
        try:
            raw=read_private(s.home,'configuration-imports','import-report-'+result['report_id']+'.json')
            report=strict_json(raw)
            source=read_private(s.home,'configuration-history','event-info-plan-'+result['source_plan_id']+'.json')
            values=json.loads(row['values_json']) if isinstance(row['values_json'],(str,bytes)) else row['values_json']
            result['status']='verified' if (isinstance(report,dict) and sha(raw)==result['report_sha256'] and sha(source)==result['source_sha256']
                and report.get('source_sha256')==result['source_sha256'] and report.get('report_id')==result['report_id']
                and report.get('source_plan_id')==result['source_plan_id'] and report.get('content_sha256')==row['content_sha256']
                and report.get('base_config_sha256')==row['base_config_sha256'] and report.get('values')==values and report.get('eligible') is True) else 'report_mismatch'
        except FileNotFoundError:result['status']='report_missing'
        except (OSError,ValueError,__import__('app').ApiError):result['status']='report_mismatch'
    return result

def view(s,db,row,verify=True,config_raw=None,generation=None):
    reasons=[];file_status='not_checked';current_sha=None
    try:current_sha=sha(config_raw if config_raw is not None else read_private(s.home,'.','config.json'))
    except (OSError,ValueError,__import__('app').ApiError):reasons.append('config_unavailable')
    if current_sha is not None and current_sha!=row['base_config_sha256']:reasons.append('base_config_changed')
    matches=row['target_hash']==target(s.home)
    if not matches:reasons.append('target_mismatch')
    if verify:
        try:
            raw=read_private(s.home,'configuration-history',row['source_file']);source=strict_json(raw)
            values=json.loads(row['values_json']) if isinstance(row['values_json'],(str,bytes)) else row['values_json']
            file_status='matches' if (sha(raw)==row['source_file_sha256'] and isinstance(source,dict)
                and set(source)=={'format','created_at','target_hash','config_sha256','values','production_enabled','automatic_deletion_enabled'}
                and source['format']=='festival-event-information-v1' and source['created_at']==row['created_at']
                and source['target_hash']==row['target_hash'] and source['config_sha256']==row['base_config_sha256']
                and source['values']==values and sha(canonical(values))==row['content_sha256']
                and source['production_enabled'] is False and source['automatic_deletion_enabled'] is False) else 'mismatch'
        except FileNotFoundError:file_status='missing'
        except (OSError,ValueError,__import__('app').ApiError):file_status='unreadable'
        if file_status!='matches':reasons.append('plan_file_changed' if file_status=='mismatch' else 'plan_file_unavailable')
    state=row['state_after'];review_id=None;reviewer=None;review_until=None
    if state=='reviewed':
        review_id=row['event_id'];reviewer=row['actor_id'];review_until=row['review_valid_until']
        if not row['actor_enabled']:reasons.append('reviewer_disabled')
        if row['actor_role']!='settings':reasons.append('reviewer_role_changed')
        if review_until is None or not row['event_time']<=s.now()<review_until:reasons.append('review_expired')
        if row['reason_code']!='g:'+(generation or require_runtime_ready(s,db)):reasons.append('restore_reconfirmation_required')
    imported=provenance(s,row,verify)
    if imported and imported['status']!='verified':
        if verify:reasons.append('import_provenance_unverified')
    effective='review_required' if reasons and state not in ('saved','withdrawn') else state
    values=lambda value:json.loads(value) if isinstance(value,(str,bytes)) else value
    return dict(plan_id=row['id'],version=row['plan_version'],created_by=row['created_by'],created_at_utc=utc(row['created_at']),
                base_values=values(row['base_values_json']),values=values(row['values_json']),content_sha256=row['content_sha256'],
                base_config_sha256=row['base_config_sha256'],source_file_status=file_status,current_config_sha256=current_sha,
                base_config_matches=current_sha==row['base_config_sha256'],state=state,effective_state=effective,reason_codes=reasons,
                review_event_id=review_id,review_valid_until_utc=utc(review_until) if review_until is not None else None,
                reviewer_id=reviewer,scope='local_display_only',import_provenance=imported,target_matches=matches)

def eligible(s,db,row,reviewed=False):
    value=view(s,db,row)
    if not value['target_matches']:fail('plan_target_mismatch')
    if value['current_config_sha256'] is None:fail('storage_unavailable',503)
    if not value['base_config_matches']:fail('config_changed')
    if value['source_file_status']!='matches':fail('plan_file_changed' if value['source_file_status']=='mismatch' else 'plan_file_unavailable')
    if value['import_provenance'] and value['import_provenance']['status']!='verified':fail('invalid_state')
    if row['state_after']=='withdrawn':fail('invalid_state')
    if reviewed and (row['state_after']!='reviewed' or value['reason_codes']):fail('review_required')
    existing=db.execute("SELECT a.id FROM event_info_apply_attempts a LEFT JOIN event_info_apply_observations o ON o.attempt_id=a.id AND o.observation_version=(SELECT MAX(v.observation_version) FROM event_info_apply_observations v WHERE v.attempt_id=a.id) WHERE a.plan_id=? AND (o.id IS NULL OR o.outcome IN ('unknown','conflict','file_written')) LIMIT 1",(row['id'],)).fetchone()
    if existing:fail('apply_reconciliation_required')
    return value

def transition(s,db,actor,plan_id,data,kind):
    settings_actor(db,actor);generation=require_runtime_ready(s,db);row=load(db,plan_id)
    if row['plan_version']!=data['expected_version']:fail('version_conflict')
    if row['content_sha256']!=data['content_sha256']:fail('content_changed')
    if kind=='withdrawn':
        if row['state_after']=='withdrawn':fail('invalid_state')
        if db.execute('SELECT 1 FROM event_info_apply_attempts WHERE plan_id=? LIMIT 1',(plan_id,)).fetchone():fail('apply_reconciliation_required')
        event(s,db,row,kind,'withdrawn',actor,data['note'],data['reason_code'])
    else:
        eligible(s,db,row)
        if kind=='review_recorded':
            if row['created_by']==actor:fail('self_review_forbidden',403)
            if row['state_after']!='review_pending':fail('invalid_state')
            event(s,db,row,kind,'reviewed',actor,data['note'],'g:'+generation,s.now()+policy(s)['review_valid_seconds'])
        else:
            if row['state_after'] not in ('saved','reviewed','review_pending'):fail('invalid_state')
            event(s,db,row,kind,'review_pending',actor,data['note'])
    return view(s,db,load(db,plan_id))

def observation(s,db,attempt,outcome,observed,evidence):
    version=db.execute('SELECT COALESCE(MAX(observation_version),0)+1 FROM event_info_apply_observations WHERE attempt_id=?',(attempt,)).fetchone()[0]
    db.execute('INSERT INTO event_info_apply_observations VALUES (?,?,?,?,?,?,?,?)',(uid(),attempt,version,outcome,observed,evidence,'local_cli',s.now()))
    s.audit(db,'local_cli','event_plan_observed',attempt)

def observe(s,db,attempt):
    try:actual=sha(read_private(s.home,'.','config.json'))
    except (OSError,ValueError,__import__('app').ApiError):actual=None
    outcome='unknown' if actual is None else 'file_written' if actual==attempt['expected_after_config_sha256'] else 'not_written' if actual==attempt['before_config_sha256'] else 'conflict'
    observation(s,db,attempt['id'],outcome,actual,'config_hash_checked')
    return outcome

def apply_reviewed(s,plan_id,expected_version):
    from recovery_kit import stopped
    from workflow_common import target_lock
    policy(s)
    with stopped(s.home),target_lock(s.home):
        with s.db(True) as db:
            require_runtime_ready(s,db);row=load(db,plan_id)
            if row['plan_version']!=expected_version:fail('version_conflict')
            value=eligible(s,db,row,True);original=read_private(s.home,'.','config.json');updated=strict_json(original)
            values=value['values'];updated['event_information']={k:v for k,v in values.items() if k not in ('service_start_utc','service_end_utc')}
            window=uid() if any(updated.get(k)!=values[k] for k in ('service_start_utc','service_end_utc')) else None
            if window:updated['service_window_id']=window
            for key in ('service_start_utc','service_end_utc'):updated[key]=values[key]
            candidate=Service.__new__(Service);candidate.home=s.home;candidate.config=updated;candidate.validate_config()
            after=canonical(updated);attempt_id=uid();prefix=attempt_id+'-event'
            db.execute('INSERT INTO event_info_apply_attempts VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                       (attempt_id,row['id'],row['event_id'],row['plan_version'],'local_cli',s.now(),uid(),row['content_sha256'],sha(original),sha(after),window,prefix))
            s.audit(db,'local_cli','event_plan_apply_requested',attempt_id)
        try:
            directory=private_dir(s.home,'configuration-history')
            for suffix,raw in [('before',original),('after',after)]:secure_new_file(directory/(prefix+'-'+suffix+'.json'),raw)
            replacement=s.home/('config-'+attempt_id+'.pending');secure_new_file(replacement,after)
            # Revalidate the review while holding the application write lock across replace.
            # The committed attempt remains evidence even if this second stage is refused.
            with s.db(True) as db:
                require_runtime_ready(s,db);fresh=load(db,plan_id);checked=view(s,db,fresh)
                if fresh['event_id']!=row['event_id'] or fresh['plan_version']!=row['plan_version'] or fresh['state_after']!='reviewed' or checked['reason_codes']:
                    fail('review_required')
                if read_private(s.home,'.','config.json')!=original:raise ValueError('Config changed')
                os.replace(replacement,s.home/'config.json')
        finally:
            with s.db(True) as db:
                attempt=db.execute('SELECT * FROM event_info_apply_attempts WHERE id=?',(attempt_id,)).fetchone()
                outcome=observe(s,db,attempt)
        return dict(applied=outcome=='file_written',attempt_id=attempt_id,restart_required=True,network_verified=False)

def reconcile(s,attempt_id):
    from recovery_kit import stopped
    from workflow_common import target_lock
    with stopped(s.home),target_lock(s.home),s.db(True) as db:
        require_runtime_ready(s,db);attempt=db.execute('SELECT * FROM event_info_apply_attempts WHERE id=?',(identifier(attempt_id),)).fetchone()
        if not attempt:fail('attempt_not_found',404)
        return dict(attempt_id=attempt_id,outcome=observe(s,db,attempt),records_preserved=True)
