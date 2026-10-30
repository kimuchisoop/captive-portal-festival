"""Explicit local maintenance commands. Nothing runs merely by importing this module."""
from pathlib import Path
import json,os,time
from app import ROOT,Service,uid,utc
from database import load_settings,initialize_schema,transaction
from security import protect_directory
from jobs import secure_new_file,set_meta
from workflow_common import canonical,private_dir,read_private,strict_json,target_lock,sha,identifier
from workflow_database import maintenance_settings,verify_contract,precheck_initialization
from workflow_generation import create_generation,require_runtime_ready

def initialize(home,sample=False,restored=False,db_settings=None,maintenance_file=None,open_service=True):
    if restored:raise ValueError('Use the explicit schema-five recovery commands')
    if not db_settings or not maintenance_file:raise ValueError('Separate runtime and maintenance credentials required')
    maintenance=maintenance_settings(maintenance_file,db_settings)
    home=Path(home).resolve()
    if home.exists():raise ValueError('Initialization needs a NEW data folder: '+str(home))
    precheck_initialization(maintenance)
    home.mkdir(mode=0o700,parents=True,exist_ok=False);protect_directory(home)
    secure_new_file(home/'initialization.incomplete',canonical(dict(id=uid(),schema_version=5)))
    config=strict_json((ROOT/'config.example.json').read_bytes())
    if sample:
        config.update(local_intake_enabled=True,event_id=uid(),service_window_id=uid(),terms_document_id=uid(),terms_version='local-draft-1',policy_version='local-test-1',
                      service_start_utc=utc(int(time.time())-60),service_end_utc=utc(int(time.time())+86400),retention_days=7,audit_retention_days=7,backup_retention_days=7)
    secure_new_file(home/'config.json',canonical(config));secure_new_file(home/'mysql.json',canonical(db_settings))
    from cryptography.fernet import Fernet
    for name,value in [('session.key',os.urandom(32)),('backup.key',Fernet.generate_key()),('mfa.key',Fernet.generate_key())]:secure_new_file(home/name,value)
    for language in ('ja','en'):secure_new_file(home/('terms.'+language+'.txt'),(ROOT/('terms.'+language+'.txt')).read_bytes())
    try:initialize_schema(maintenance,ROOT/'schema-v5.sql')
    except Exception as error:
        # MySQL DDL commits as it goes. Record what exists; nothing is dropped or deleted automatically.
        try:
            with transaction(maintenance) as db:created=sorted(r[0] for r in db.execute('SHOW TABLES').fetchall())
        except Exception:created=None
        secure_new_file(home/'initialization.failed.json',canonical(dict(error=type(error).__name__+': '+str(error),database=maintenance['database'],tables_created=created,
            next_steps=['Fix the cause shown in error','Have the DB administrator recreate an EMPTY database (the failed attempt left only empty tables)',
                        'Rename this data folder aside (it is kept, not deleted)','Run init again with a NEW data folder'])))
        raise ValueError('Initialization failed after creating '+(str(len(created)) if created is not None else 'unknown')+' tables; see '+str(home/'initialization.failed.json')) from error
    with transaction(maintenance,True) as db:
        verify_contract(db);set_meta(db,'schema_version','5');create_generation(db,int(time.time()))
    history=private_dir(home,'migration-history');destination=history/('initialization-'+uid()+'.completed.json')
    if not destination.resolve().is_relative_to(home):raise ValueError('Unsafe initialization marker destination')
    os.rename(home/'initialization.incomplete',destination)
    # The service account's column grants can only be applied once the tables exist, so the CLI does not reconnect here.
    return Service(home) if open_service else None

def register(sub):
    upgrade=sub.add_parser('upgrade-schema5',help='Stopped explicit additive 4-to-5 candidate; retain all failures')
    upgrade.add_argument('--maintenance-db-config',type=Path,required=True)
    prepare=sub.add_parser('prepare-event-plan-import',help='Prepare retained evidence for a legacy basename')
    prepare.add_argument('--source-basename',required=True)
    apply=sub.add_parser('apply-reviewed-plan',help='Stopped application of a DB-registered independently reviewed plan')
    apply.add_argument('--plan-id',required=True);apply.add_argument('--expected-version',type=int,required=True)
    reconcile=sub.add_parser('reconcile-plan-application');reconcile.add_argument('--attempt-id',required=True)
    sub.add_parser('release-schema5-recovery')
    for command in ('fail-restored-export','release-restored-export'):
        parser=sub.add_parser(command);parser.add_argument('--export-id',required=True)
    for command in ('restore-schema5','restore-schema5-kit'):
        parser=sub.add_parser(command)
        for option in ('source','key-file','db-config','maintenance-db-config'):parser.add_argument('--'+option,type=Path,required=True)
    sub.add_parser('workflow-status')
    diagnosis=sub.add_parser('diagnose-workflow',help='Read-only startup reasons; default offline; never releases guards')
    diagnosis.add_argument('--include-db',action='store_true',help='Explicit read-only MySQL metadata connection')
    prepare_policy=sub.add_parser('prepare-workflow-policy',help='Retain a proposal and diff without activation')
    prepare_policy.add_argument('--proposal-file',type=Path,required=True)
    prepare_policy.add_argument('--expected-config-sha256',required=True)
    apply_policy=sub.add_parser('apply-workflow-policy',help='Stopped activation only with explicit local approval evidence')
    apply_policy.add_argument('--plan-id',required=True);apply_policy.add_argument('--expected-plan-sha256',required=True)
    apply_policy.add_argument('--approval-file',type=Path,required=True)
    sub.add_parser('reconcile-workflow-policy',help='Stopped file/DB reconciliation; retain conflicts and guards')

def release_export(s,export_id):
    from recovery_kit import stopped
    from archive_repository import seal
    with stopped(s.home),target_lock(s.home),s.db(True) as db:
        generation=require_runtime_ready(s,db);export_id=identifier(export_id)
        job=db.execute('SELECT * FROM consent_archive_exports WHERE id=?',(export_id,)).fetchone()
        snapshot=db.execute('SELECT * FROM consent_archive_snapshots WHERE export_id=?',(export_id,)).fetchone()
        if not job or job['state']!='ready' or not snapshot or snapshot['state']!='ready':raise ValueError('Ready evidence required')
        if seal(db,snapshot['id'])!=(snapshot['item_count'],snapshot['rows_sha256']):raise ValueError('Copy integrity differs')
        history=private_dir(s.home,'restore-history');directory=history/generation
        if __import__('filesystem_guard').is_link(directory):raise ValueError('Linked release history')
        directory.mkdir(exist_ok=True);protect_directory(directory)
        path=directory/('export-'+export_id+'.json')
        value=dict(export_id=export_id,snapshot_id=snapshot['id'],rows_sha256=snapshot['rows_sha256'],item_count=snapshot['item_count'],generation=generation,actor='local_cli',released_at=s.now())
        if path.exists():
            original=strict_json(read_private(s.home,'restore-history/'+generation,path.name))
            if any(original.get(k)!=value[k] for k in ('export_id','snapshot_id','rows_sha256','item_count','generation')):raise ValueError('Receipt differs')
        else:secure_new_file(path,canonical(value))
        set_meta(db,'workflow5_export_release_'+export_id,canonical(dict(generation=generation,rows_sha256=snapshot['rows_sha256'],receipt_sha256=sha(read_private(s.home,'restore-history/'+generation,path.name)))).decode())
        s.audit(db,'local_cli','consent_archive_recovery_released',export_id)
        return dict(released=True,export_id=export_id,records_preserved=True)

def handle(args):
    command=args.command
    if command=='diagnose-workflow':
        from workflow_diagnostics import diagnose
        result=diagnose(args.home,args.include_db)
    elif command=='prepare-workflow-policy':
        from workflow_policy_cli import prepare
        result=prepare(args.home,args.proposal_file,args.expected_config_sha256)
    elif command=='apply-workflow-policy':
        from workflow_policy_cli import apply
        result=apply(args.home,args.plan_id,args.expected_plan_sha256,args.approval_file)
    elif command=='reconcile-workflow-policy':
        from workflow_policy_cli import reconcile
        result=reconcile(args.home)
    elif command=='upgrade-schema5':
        from workflow_database import migrate
        result=migrate(args.home,args.maintenance_db_config)
    elif command=='release-schema5-recovery':
        from workflow_generation import release_recovery
        result=release_recovery(args.home)
    elif command in ('restore-schema5','restore-schema5-kit'):
        if command=='restore-schema5-kit':
            from workflow_kit import restore_kit
            result=restore_kit(args.source,args.key_file,args.home,load_settings(args.db_config),args.maintenance_db_config)
        else:
            from workflow_backup import restore
            result=restore(args.source,args.key_file,args.home,load_settings(args.db_config),args.maintenance_db_config)
    elif command in ('prepare-event-plan-import','apply-reviewed-plan','reconcile-plan-application','fail-restored-export','release-restored-export','workflow-status'):
        s=Service(args.home)
        if command=='prepare-event-plan-import':
            from event_plan_import import prepare
            result=prepare(s,args.source_basename)
        elif command=='apply-reviewed-plan':
            from event_info_repository import apply_reviewed
            result=apply_reviewed(s,args.plan_id,args.expected_version)
        elif command=='reconcile-plan-application':
            from event_info_repository import reconcile
            result=reconcile(s,args.attempt_id)
        elif command=='release-restored-export':result=release_export(s,args.export_id)
        elif command=='fail-restored-export':
            from recovery_kit import stopped
            from archive_repository import mark_failed
            with stopped(s.home),target_lock(s.home):
                with s.db() as db:
                    require_runtime_ready(s,db)
                    row=db.execute('SELECT state FROM consent_archive_exports WHERE id=?',(identifier(args.export_id),)).fetchone()
                    if not row or row['state'] not in ('queued','preparing'):raise ValueError('Interrupted export required')
                mark_failed(s,args.export_id,'preparation_interrupted',allow_old_generation=True,actor_type='recovery_cli')
            result=dict(export_id=args.export_id,failed_explicitly=True,records_preserved=True)
        else:
            from workflow_generation import runtime_observations
            with s.db() as db:result=dict(schema_version=5,generation=require_runtime_ready(s,db),runtime=runtime_observations(s,db),policy_approved=s.config.get('workflow_policy',{}).get('approved') is True,production_enabled=False,network_verified=False)
    else:return False
    print(json.dumps(result,ensure_ascii=False));return True
