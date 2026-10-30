"""Fresh/restore lineage, guarded startup and configured runtime observations."""
from contextlib import contextmanager
from pathlib import Path
import json,os,threading,time,sys
from app import Service,uid
from database import transaction,validate_settings
from workflow_common import canonical,sha,identifier,read_private,private_dir,strict_json,target_lock,policy
from jobs import secure_new_file,set_meta

def lineage(db):
    values={r['name']:r['value'] for r in db.execute("SELECT name,value FROM meta WHERE name IN ('runtime5_generation','runtime5_origin','restored_requires_review','runtime5_release_receipt_sha256','runtime5_restore_id')").fetchall()}
    identifier(values.get('runtime5_generation'))
    if values.get('runtime5_origin') not in ('fresh','restored'):raise ValueError('Unknown workflow origin')
    return values

def require_runtime_ready(s,db=None):
    if db is None:
        with s.db() as connection:return require_runtime_ready(s,connection)
    return require_lineage_ready(s,db)

def require_lineage_ready(s,db,allow_policy_guard=False):
    # The opt-in is restricted to the stopped policy reconciliation CLI.
    values=lineage(db)
    if values.get('restored_requires_review')!='false':raise ValueError('Recovery review required')
    markers=('restore.incomplete','upgrade.incomplete','initialization.incomplete')+(() if allow_policy_guard else ('policy-apply.incomplete',))
    if any((s.home/name).exists() or __import__('filesystem_guard').is_link(s.home/name) for name in markers):
        raise ValueError('Incomplete operation')
    if values['runtime5_origin']=='restored':
        restored=identifier(values.get('runtime5_restore_id'));generation=values['runtime5_generation']
        raw=read_private(s.home,'restore-history/'+restored,'release-'+generation+'.json')
        receipt=strict_json(raw)
        if sha(raw)!=values.get('runtime5_release_receipt_sha256') or receipt.get('generation')!=generation or receipt.get('restore_id')!=restored:
            raise ValueError('Recovery receipt mismatch')
    return values['runtime5_generation']

def create_generation(db,now,origin='fresh',restore_id=None):
    generation=uid()
    for key,value in {'runtime5_generation':generation,'runtime5_origin':origin,
                      'runtime5_generation_started_at':now,'restored_requires_review':'true' if origin=='restored' else 'false'}.items():
        set_meta(db,key,value)
    if restore_id:set_meta(db,'runtime5_restore_id',restore_id)
    return generation

class OpsContext:
    """Local maintenance only; never use this context to bypass HTTP startup guards."""
    def __init__(self,home,settings=None):
        self.home=Path(home).resolve();raw=read_private(self.home,'.','config.json')
        self.config=strict_json(raw);self.loaded_config_sha256=sha(raw)
        self.db_settings=settings or validate_settings(strict_json(read_private(self.home,'.','mysql.json')));self.clock=time.time
        self.key=read_private(self.home,'.','session.key')
        Service.validate_config(self)
    def now(self):return int(self.clock())
    def db(self,write=False):return transaction(self.db_settings,write)
    audit=Service.audit

def beat(s,kind,instance):
    with s.db(True) as db:
        generation=require_runtime_ready(s,db)
        value=canonical(dict(instance=instance,generation=generation,config_sha256=s.loaded_config_sha256,seen_at=s.now())).decode()
        if len(value)>255:raise ValueError('Heartbeat too long')
        set_meta(db,'runtime5_'+kind,value)

@contextmanager
def runtime_heartbeat(s,kind):
    if kind not in ('app','worker'):raise ValueError('Unknown runtime')
    if sha(read_private(s.home,'.','config.json'))!=s.loaded_config_sha256:raise ValueError('Configuration changed before runtime lock acquisition')
    if s.config.get('workflow_policy',{}).get('approved') is not True:
        yield
        return
    configured=policy(s)
    stop=threading.Event();instance=s.instance_id;beat(s,kind,instance)
    def loop():
        while not stop.wait(configured['heartbeat_seconds']):
            try:beat(s,kind,instance)
            except Exception:sys.stderr.write('workflow_heartbeat_failed\n');sys.stderr.flush()
    thread=threading.Thread(target=loop,name='workflow-heartbeat-'+kind,daemon=True);thread.start()
    try:yield
    finally:stop.set();thread.join(timeout=20)

def runtime_observations(s,db):
    generation=require_runtime_ready(s,db);result={}
    if s.config.get('workflow_policy',{}).get('approved') is not True:
        return {kind:dict(state='unknown',instance=None,config_sha256=None,seen_at_utc=None) for kind in ('app','worker')}
    configured=policy(s)
    for kind in ('app','worker'):
        row=db.execute('SELECT value FROM meta WHERE name=?',('runtime5_'+kind,)).fetchone()
        value=None
        try:
            if row:value=strict_json(row['value'].encode())
            valid=(isinstance(value,dict) and set(value)=={'instance','generation','config_sha256','seen_at'}
                   and value['generation']==generation and type(value['seen_at']) is int and 0<=s.now()-value['seen_at']<configured['stale_after_seconds'])
            if valid:
                identifier(value['instance'])
                valid=isinstance(value['config_sha256'],str) and bool(__import__('workflow_common').HEX.fullmatch(value['config_sha256']))
        except (ValueError,TypeError,KeyError,__import__('app').ApiError):valid=False
        result[kind]=dict(state='active' if valid else 'unknown',instance=value.get('instance') if valid else None,config_sha256=value.get('config_sha256') if valid else None,
                          seen_at_utc=__import__('app').utc(value['seen_at']) if valid else None)
    return result

def release_recovery(home):
    from recovery_kit import stopped
    home=Path(home).resolve()
    with stopped(home),target_lock(home):
        s=OpsContext(home);marker=strict_json(read_private(home,'.','restore.incomplete'))
        restore_id=identifier(marker['restore_id']);directory=private_dir(home,'restore-history')/restore_id
        if not directory.resolve().is_relative_to(home):raise ValueError('Outside recovery root')
        directory.mkdir(exist_ok=True)
        report_raw=read_private(home,'restore-history/'+restore_id,'report.json');report=strict_json(report_raw)
        if not report.get('raw_verified') or report.get('restore_id')!=restore_id or s.config.get('local_intake_enabled') is not False:
            raise ValueError('Recovery evidence incomplete')
        with s.db(True) as db:
            values=lineage(db);generation=values['runtime5_generation']
            if values['runtime5_origin']!='restored' or values.get('runtime5_restore_id')!=restore_id:raise ValueError('Recovery target mismatch')
            if db.execute('SELECT count(*) FROM sessions').fetchone()[0]:raise ValueError('Restored sessions present')
            if db.execute("SELECT count(*) FROM grants WHERE authorization_status NOT IN ('expired','revoked')").fetchone()[0]:raise ValueError('Restored active grants')
            if db.execute('SELECT count(*) FROM mfa_settings WHERE enabled=1 AND needs_reset=0').fetchone()[0]:raise ValueError('MFA reset missing')
            receipt=directory/('release-'+generation+'.json')
            already_released=values.get('restored_requires_review')=='false'
            if already_released and not receipt.exists():raise ValueError('Committed release receipt missing')
            value=dict(restore_id=restore_id,generation=generation,report_sha256=sha(report_raw),actor='local_cli',released_at=s.now())
            if receipt.exists():
                existing=read_private(home,'restore-history/'+restore_id,receipt.name)
                parsed=strict_json(existing)
                if any(parsed.get(key)!=value[key] for key in ('restore_id','generation','report_sha256','actor')):raise ValueError('Receipt mismatch')
            else:secure_new_file(receipt,canonical(value))
            receipt_sha=sha(read_private(home,'restore-history/'+restore_id,receipt.name))
            if already_released:
                if values.get('runtime5_release_receipt_sha256')!=receipt_sha:raise ValueError('Committed receipt differs')
            else:
                set_meta(db,'runtime5_release_receipt_sha256',receipt_sha)
                set_meta(db,'restored_requires_review','false');s.audit(db,'local_cli','schema5_recovery_released',restore_id)
        source=home/'restore.incomplete';destination=directory/'restore.incomplete'
        if not source.resolve().is_relative_to(home) or not destination.resolve().is_relative_to(home) or destination.exists():raise ValueError('Unsafe marker destination')
        os.rename(source,destination)
        return dict(released=True,generation=generation,records_preserved=True)
