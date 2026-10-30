"""Read-only diagnosis independent of Service construction; no guard release or lock probes."""
from pathlib import Path
from types import SimpleNamespace
import time
from app import Service
from database import validate_settings,transaction
from workflow_common import read_private,strict_json,sha
from workflow_generation import require_runtime_ready
from filesystem_guard import is_link

MARKERS=('initialization.incomplete','upgrade.incomplete','restore.incomplete','policy-apply.incomplete')

def diagnose(home,include_db=False):
    home=Path(home).resolve();checks=[];blockers=[]
    def note(code,state,blocking=False):
        checks.append(dict(code=code,state=state))
        if blocking:blockers.append(code)
    for name in MARKERS:
        try:
            linked=is_link(home/name);present=linked or (home/name).exists()
            note(name,'unsafe_link' if linked else 'present' if present else 'absent',present)
        except OSError:note(name,'unreadable',True)
    config=None;config_sha=None
    try:
        raw=read_private(home,'.','config.json');config=strict_json(raw);config_sha=sha(raw)
        if not isinstance(config,dict):raise ValueError('Object required')
        note('config_json','readable')
    except Exception:config=None;config_sha=None;note('config_json','unavailable_or_invalid',True)
    terms_ok=True
    for language in ('ja','en'):
        try:
            if not read_private(home,'.','terms.'+language+'.txt').decode('utf-8').strip():raise ValueError('Empty terms')
            note('terms_'+language,'readable')
        except Exception:terms_ok=False;note('terms_'+language,'unavailable_or_invalid',True)
    try:
        if len(read_private(home,'.','session.key'))!=32:raise ValueError('Invalid key')
        note('session_key','readable_valid_length')
    except Exception:note('session_key','unavailable_or_invalid',True)
    if config is not None and terms_ok:
        try:
            candidate=Service.__new__(Service);candidate.home=home;candidate.config=config;candidate.validate_config()
            note('config_constraints','accepted')
        except Exception:note('config_constraints','invalid',True)
    else:note('config_constraints','not_checked')
    if config is not None:
        note('workflow_policy','approved' if isinstance(config.get('workflow_policy'),dict) and config['workflow_policy'].get('approved') is True else 'unapproved_features_held')
    if include_db:
        try:
            settings=validate_settings(strict_json(read_private(home,'.','mysql.json')))
            with transaction(settings) as db:
                row=db.execute("SELECT value FROM meta WHERE name='schema_version'").fetchone()
                if not row or row['value']!='5':raise ValueError('Schema five required')
                from workflow_database import verify_contract
                verify_contract(db);note('mysql_schema_contract','accepted_names_types_pk_engine')
                flags={r['name']:r['value'] for r in db.execute("SELECT name,value FROM meta WHERE name IN ('runtime5_origin','restored_requires_review')").fetchall()}
                note('recovery_review','required' if flags.get('restored_requires_review')!='false' else 'released',flags.get('restored_requires_review')!='false')
                context=SimpleNamespace(home=home)
                try:require_runtime_ready(context,db);note('lineage_and_receipt','accepted')
                except Exception:note('lineage_and_receipt','blocked_or_invalid',True)
        except Exception:note('mysql_read_only_diagnosis','unavailable_or_invalid',True)
    else:note('mysql_read_only_diagnosis','not_requested')
    return dict(format='festival-workflow-diagnosis-v1',release='0.11.10-rc1',checked_at=int(time.time()),
                startup_eligibility='blocked' if blockers else 'checks_satisfied' if include_db else 'not_fully_checked',
                blockers=blockers,checks=checks,config_sha256=config_sha,database_requested=include_db,
                locks_checked=False,runtime_health_verified=False,network_verified=False,guards_released=False,home_files_written=False)
