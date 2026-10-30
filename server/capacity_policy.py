"""Provisional warning budgets; explicit stopped-service application, never purge."""
import hashlib
import json
import os
from filesystem_guard import is_link, regular
from app import uid
from jobs import secure_new_file
from security import protect_directory

GIB=1024**3
LIMITS=('db_warning_bytes','backup_warning_bytes','min_free_bytes')

def make_plan(s):
    from operations import storage_status
    usage=storage_status(s)
    if not usage['backup_bytes_complete']:raise ValueError('Backup capacity is incomplete; inspect retained files before planning')
    return dict(format='festival-capacity-plan-v1',created_at=s.now(),
        target_hash=hashlib.sha256(str(s.home).encode()).hexdigest(),
        config_sha256=hashlib.sha256((s.home/'config.json').read_bytes()).hexdigest(),
        limits=dict(db_warning_bytes=max(GIB,usage['database_allocated_bytes']*4),
                    backup_warning_bytes=max(4*GIB,usage['backup_bytes']*4),min_free_bytes=5*GIB),
        measured=dict(database_allocated_bytes=usage['database_allocated_bytes'],backup_bytes=usage['backup_bytes'],
                      application_disk_free_bytes=usage['application_disk_free_bytes']),
        provisional=True,database_disk_free_bytes=None,automatic_deletion_enabled=False,
        notes=['暫定値。MySQLは推定使用量の4倍または1GiB、バックアップは現在量の4倍または4GiB。',
               '空き容量の警告は5GiB。MySQLサーバー本体・他システムとの共用分は別途確認。',
               '3,500人は1日の来場者数であり、同時接続数や保存量の実測とは扱わない。'])

def apply_plan(s,plan):
    if (not isinstance(plan,dict) or plan.get('format')!='festival-capacity-plan-v1'
        or plan.get('automatic_deletion_enabled') is not False or plan.get('provisional') is not True): raise ValueError('Invalid capacity plan')
    if plan.get('target_hash')!=hashlib.sha256(str(s.home).encode()).hexdigest(): raise ValueError('Plan target mismatch')
    config_path=s.home/'config.json';original=config_path.read_bytes()
    if plan.get('config_sha256')!=hashlib.sha256(original).hexdigest(): raise ValueError('Plan is stale')
    limits=plan.get('limits')
    if not isinstance(limits,dict) or set(limits)!=set(LIMITS): raise ValueError('Invalid limits')
    if any(type(v) is not int or not 1<=v<=2**63-1 for v in limits.values()): raise ValueError('Invalid capacity values')
    from workflow_generation import stopped_config_change
    with stopped_config_change(s):
        # Recheck after lock acquisition to avoid replacing a newly edited configuration.
        if config_path.read_bytes()!=original: raise ValueError('Configuration changed')
        history=s.home/'configuration-history'
        if is_link(history):raise ValueError('Linked configuration history')
        history.mkdir(exist_ok=True);protect_directory(history)
        change=uid();secure_new_file(history/(change+'-before.json'),original)
        secure_new_file(history/(change+'-capacity-plan.json'),json.dumps(plan,ensure_ascii=False,indent=2).encode())
        updated=json.loads(original);updated.update(limits)
        from transport import validate_transport
        validate_transport(updated)
        with s.db(True) as db: s.audit(db,'local_cli','capacity_change_requested',change)
        pending=history/(change+'-after.json');secure_new_file(pending,json.dumps(updated,ensure_ascii=False,indent=2).encode())
        # Copy to a new private file, so history is preserved as well as the old settings.
        replacement=s.home/('config-'+change+'.pending');secure_new_file(replacement,pending.read_bytes())
        regular(config_path);os.replace(replacement,config_path)
        with s.db(True) as db: s.audit(db,'local_cli','capacity_changed',change)
