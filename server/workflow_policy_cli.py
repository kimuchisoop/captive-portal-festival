"""Stopped policy activation with explicit local approval and retained crash evidence."""
from pathlib import Path
import os
from app import Service,uid,utc,timestamp
from jobs import secure_new_file,set_meta
from workflow_common import canonical,strict_json,read_private,private_dir,target,target_lock,sha,identifier,HEX,validate_policy
from workflow_generation import OpsContext,require_runtime_ready,lineage
from workflow_database import verify_contract
from recovery_kit import stopped

PLAN_FORMAT='festival-workflow-policy-plan-v1'
APPROVAL_FORMAT='festival-workflow-policy-approval-v1'
MARKER='policy-apply.incomplete'

def external_json(path):
    path=Path(path).absolute()
    return strict_json(read_private(path.parent,'.',path.name))

def checked_config(s,raw,proposal):
    validate_policy(proposal,False)
    value=strict_json(raw)
    desired={**proposal,'approved':True}
    if value.get('workflow_policy')==desired:raise ValueError('No policy change required')
    value['workflow_policy']=desired
    candidate=Service.__new__(Service);candidate.home=s.home;candidate.config=value
    candidate.validate_config()
    return canonical(value)

def prepare(home,proposal_file,expected_config_sha256):
    home=Path(home).resolve()
    if not HEX.fullmatch(expected_config_sha256):raise ValueError('Expected config SHA256 required')
    proposal=external_json(proposal_file);validate_policy(proposal,False)
    with target_lock(home):
        s=OpsContext(home);original=read_private(home,'.','config.json')
        if sha(original)!=expected_config_sha256:raise ValueError('Config differs')
        after=checked_config(s,original,proposal)
        with s.db(True) as db:
            verify_contract(db);generation=require_runtime_ready(s,db)
            plan_id=uid()
            plan=dict(format=PLAN_FORMAT,plan_id=plan_id,created_at=s.now(),target_hash=target(home),generation=generation,
                      before_config_sha256=sha(original),after_config_sha256=sha(after),proposal=proposal,
                      production_enabled=False,automatic_deletion_enabled=False)
            if read_private(home,'.','config.json')!=original:raise ValueError('Config changed')
            raw=canonical(plan);directory=private_dir(home,'configuration-history')
            secure_new_file(directory/('policy-plan-'+plan_id+'.json'),raw)
            s.audit(db,'local_cli','workflow_policy_plan_prepared',plan_id)
        old=s.config.get('workflow_policy') or {}
        return dict(plan_id=plan_id,plan_sha256=sha(raw),applied=False,approval_required=True,
                    differences=[dict(setting=k,before=old.get(k),after=v) for k,v in {**proposal,'approved':True}.items() if old.get(k)!=v])

def checked_plan(s,plan_id,expected_sha,original,generation):
    plan_id=identifier(plan_id)
    raw=read_private(s.home,'configuration-history','policy-plan-'+plan_id+'.json');plan=strict_json(raw)
    keys={'format','plan_id','created_at','target_hash','generation','before_config_sha256','after_config_sha256','proposal','production_enabled','automatic_deletion_enabled'}
    if not isinstance(plan,dict) or set(plan)!=keys or not HEX.fullmatch(expected_sha) or sha(raw)!=expected_sha:raise ValueError('Plan differs')
    if (plan['format']!=PLAN_FORMAT or plan['plan_id']!=plan_id or type(plan['created_at']) is not int or not 0<=plan['created_at']<=s.now()
        or plan['target_hash']!=target(s.home) or plan['generation']!=generation or plan['before_config_sha256']!=sha(original)
        or plan['production_enabled'] is not False or plan['automatic_deletion_enabled'] is not False):raise ValueError('Plan target differs')
    after=checked_config(s,original,plan['proposal'])
    if sha(after)!=plan['after_config_sha256']:raise ValueError('Planned config differs')
    return raw,after

def checked_approval(s,value,plan_id,plan_sha,plan_created_at):
    keys={'format','plan_id','plan_sha256','decision_id','approved_by','decided_at_utc','confirmed'}
    if not isinstance(value,dict) or set(value)!=keys or value['format']!=APPROVAL_FORMAT or value['confirmed'] is not True:raise ValueError('Explicit approval required')
    if value['plan_id']!=plan_id or value['plan_sha256']!=plan_sha:raise ValueError('Approval target differs')
    identifier(value['decision_id']);name=value['approved_by']
    if not isinstance(name,str) or name!=name.strip() or not 1<=len(name)<=120 or any(ord(c)<32 for c in name):raise ValueError('Approver required')
    when=timestamp(value['decided_at_utc'])
    if utc(when)!=value['decided_at_utc'] or not plan_created_at<=when<=s.now():raise ValueError('Approval time differs')
    return canonical(value)

def apply(home,plan_id,expected_sha,approval_file):
    home=Path(home).resolve();approval=external_json(approval_file)
    with stopped(home),target_lock(home):
        s=OpsContext(home);original=read_private(home,'.','config.json')
        attempt_id=uid();directory=private_dir(home,'configuration-history')
        with s.db(True) as db:
            verify_contract(db);generation=require_runtime_ready(s,db)
            plan_raw,after=checked_plan(s,plan_id,expected_sha,original,generation)
            approval_raw=checked_approval(s,approval,plan_id,expected_sha,strict_json(plan_raw)['created_at'])
            prefix='policy-apply-'+attempt_id
            attempt=dict(format='festival-workflow-policy-attempt-v1',attempt_id=attempt_id,plan_id=plan_id,plan_sha256=sha(plan_raw),
                         approval_sha256=sha(approval_raw),generation=generation,target_hash=target(home),
                         before_config_sha256=sha(original),after_config_sha256=sha(after),created_at=s.now())
            for suffix,raw in [('before',original),('after',after),('approval',approval_raw),('attempt',canonical(attempt))]:
                secure_new_file(directory/(prefix+'-'+suffix+'.json'),raw)
            pending=home/(prefix+'.pending');secure_new_file(pending,after)
            if read_private(home,'.','config.json')!=original:raise ValueError('Config changed')
            secure_new_file(home/MARKER,canonical(dict(attempt_id=attempt_id,attempt_sha256=sha(canonical(attempt)))))
            # A failed replace or DB commit deliberately leaves the guard and all evidence.
            os.replace(pending,home/'config.json')
            set_meta(db,'workflow5_policy_apply_'+attempt_id,sha(after))
            s.audit(db,'local_cli','workflow_policy_config_written',attempt_id)
        return _finish(s,attempt,True)

def _finish(s,attempt,written):
    attempt_id=attempt['attempt_id'];directory=private_dir(s.home,'configuration-history')
    marker=strict_json(read_private(s.home,'.',MARKER))
    if marker!=dict(attempt_id=attempt_id,attempt_sha256=sha(canonical(attempt))):raise ValueError('Guard differs')
    actual=sha(read_private(s.home,'.','config.json'))
    if actual!=attempt['after_config_sha256' if written else 'before_config_sha256']:raise ValueError('Config changed after commit')
    destination=directory/('policy-apply-'+attempt_id+'-'+('completed' if written else 'not-written')+'.json')
    if destination.exists() or __import__('filesystem_guard').is_link(destination):raise ValueError('Completion evidence exists')
    os.rename(s.home/MARKER,destination)
    return dict(attempt_id=attempt_id,applied=written,restart_required=written,records_preserved=True,network_verified=False)

def reconcile(home):
    home=Path(home).resolve()
    with stopped(home),target_lock(home):
        s=OpsContext(home);marker=strict_json(read_private(home,'.',MARKER))
        if not isinstance(marker,dict) or set(marker)!={'attempt_id','attempt_sha256'}:raise ValueError('Invalid policy guard')
        attempt_id=identifier(marker['attempt_id']);prefix='policy-apply-'+attempt_id
        raw=read_private(home,'configuration-history',prefix+'-attempt.json');attempt=strict_json(raw)
        keys={'format','attempt_id','plan_id','plan_sha256','approval_sha256','generation','target_hash','before_config_sha256','after_config_sha256','created_at'}
        if sha(raw)!=marker['attempt_sha256'] or not isinstance(attempt,dict) or set(attempt)!=keys or attempt['format']!='festival-workflow-policy-attempt-v1' or attempt['attempt_id']!=attempt_id:raise ValueError('Attempt differs')
        before=read_private(home,'configuration-history',prefix+'-before.json');after=read_private(home,'configuration-history',prefix+'-after.json')
        approval_raw=read_private(home,'configuration-history',prefix+'-approval.json')
        if (sha(before),sha(after),sha(approval_raw))!=(attempt['before_config_sha256'],attempt['after_config_sha256'],attempt['approval_sha256']):raise ValueError('Evidence differs')
        with s.db(True) as db:
            verify_contract(db);values=lineage(db);generation=values['runtime5_generation']
            # Validate all other startup guards and any restored receipt without removing the policy guard.
            from workflow_generation import require_lineage_ready
            require_lineage_ready(s,db,allow_policy_guard=True)
            if generation!=attempt['generation'] or target(home)!=attempt['target_hash']:raise ValueError('Attempt target differs')
            plan_raw,computed=checked_plan(s,attempt['plan_id'],attempt['plan_sha256'],before,generation)
            checked_approval(s,strict_json(approval_raw),attempt['plan_id'],attempt['plan_sha256'],strict_json(plan_raw)['created_at'])
            if computed!=after:raise ValueError('After evidence differs')
            receipt=db.execute('SELECT value FROM meta WHERE name=?',('workflow5_policy_apply_'+attempt_id,)).fetchone()
            actual=sha(read_private(home,'.','config.json'))
            if actual==attempt['after_config_sha256'] and receipt and receipt['value']==actual:written=True
            elif actual==attempt['before_config_sha256'] and receipt is None:written=False
            else:raise ValueError('File and database differ; preserve guard for manual recovery')
            s.audit(db,'local_cli','workflow_policy_reconciled_written' if written else 'workflow_policy_reconciled_not_written',attempt_id)
        return _finish(s,attempt,written)
