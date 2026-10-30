"""Record measured backup checks. No plaintext dump or overwrite of an existing database."""
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid
from cryptography.fernet import Fernet,InvalidToken
from database import DatabaseError,transaction,table_health
from operations import BACKUP_NAME
from filesystem_guard import is_link

MAX_BACKUP_BYTES=256*1024*1024
WEB_VERIFY_BYTES=64*1024*1024

def backup_path(s,filename):
    if not isinstance(filename,str) or not BACKUP_NAME.fullmatch(filename): raise ValueError('Invalid backup name')
    uuid.UUID(BACKUP_NAME.fullmatch(filename)[2])
    parent=s.home/'backups'
    if is_link(parent): raise ValueError('Linked backup directory')
    path=parent/filename
    if is_link(path): raise ValueError('Linked backup file')
    return path

def inspect_file(s,filename,key_file=None):
    from jobs import inspect_snapshot
    path=backup_path(s,filename)
    info=path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode): raise ValueError('Not a regular file')
    if filename.endswith('.sffbackup'):
        from stream_backup import inspect_dispatch as inspect,file_hash
        before_hash=file_hash(path)
        snapshot=inspect(path,Path(key_file or s.home/'backup.key').read_bytes())
        if file_hash(path)!=before_hash: raise ValueError('Source changed during verification')
        proof=dict(ciphertext_sha256=before_hash,file_bytes=info.st_size,file_mtime_ns=info.st_mtime_ns)
        after=path.stat(follow_symlinks=False)
        if (info.st_size,info.st_mtime_ns)!=(after.st_size,after.st_mtime_ns): raise ValueError('File changed')
        return proof,snapshot
    if info.st_size>MAX_BACKUP_BYTES: raise OverflowError('Verifier size limit')
    with path.open('rb') as handle: encrypted=handle.read(MAX_BACKUP_BYTES+1)
    after=path.stat(follow_symlinks=False)
    if len(encrypted)>MAX_BACKUP_BYTES: raise OverflowError('Verifier size limit')
    if (info.st_size,info.st_mtime_ns)!=(after.st_size,after.st_mtime_ns): raise ValueError('File changed during verification')
    proof=dict(ciphertext_sha256=hashlib.sha256(encrypted).hexdigest(),file_bytes=after.st_size,file_mtime_ns=after.st_mtime_ns)
    snapshot=inspect_snapshot(Fernet(Path(key_file or s.home/'backup.key').read_bytes()).decrypt(encrypted))
    return proof,snapshot

def store_check(s,db,filename,stage,status,code,proof,actor):
    from app import uid,utc
    check_id=uid()
    db.execute('INSERT INTO backup_checks (id,filename,stage,status,code,ciphertext_sha256,file_bytes,file_mtime_ns,actor,checked_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
               (check_id,filename,stage,status,code,proof.get('ciphertext_sha256'),proof.get('file_bytes'),proof.get('file_mtime_ns'),actor,s.now()))
    s.audit(db,actor,'backup_'+stage+'_checked',check_id)
    return dict(check_id=check_id,filename=filename,stage=stage,status=status,code=code,
                checked_at_utc=utc(s.now()),**proof)

def verification_summary(s,item,db):
    path=backup_path(s,item['filename']);info=path.stat(follow_symlinks=False)
    result={}
    for stage in ('decrypt','restore'):
        row=db.execute('SELECT id,status,code,checked_at,ciphertext_sha256,file_bytes,file_mtime_ns FROM backup_checks WHERE filename=? AND stage=? ORDER BY seq DESC LIMIT 1',
                       (item['filename'],stage)).fetchone()
        if not row: result[stage]=None;continue
        from app import utc
        matches=(row['file_bytes'],row['file_mtime_ns'])==(info.st_size,info.st_mtime_ns)
        result[stage]=dict(check_id=row['id'],status=row['status'] if matches else 'file_changed',code=row['code'],
                           checked_at_utc=utc(row['checked_at']),ciphertext_sha256=row['ciphertext_sha256'])
    return result

def decrypt_check(s,filename,actor='local_cli',key_file=None,db=None):
    backup_path(s,filename)  # Invalid names are rejected rather than recorded as attempts.
    proof={}
    try: proof,_=inspect_file(s,filename,key_file);status,code='passed','authenticated_snapshot'
    except InvalidToken: status,code='failed','authentication_failed'
    except OverflowError: status,code='failed','verifier_size_limit'
    except (ValueError,TypeError,KeyError): status,code='failed','snapshot_invalid'
    except OSError: status,code='failed','file_or_key_unavailable'
    # Capture metadata even for failed authentication; no plaintext or exception text is retained.
    if not proof:
        try:
            info=backup_path(s,filename).stat(follow_symlinks=False)
            proof=dict(file_bytes=info.st_size,file_mtime_ns=info.st_mtime_ns)
        except OSError: pass
    if db is not None: return store_check(s,db,filename,'decrypt',status,code,proof,actor)
    with s.db(True) as connection: return store_check(s,connection,filename,'decrypt',status,code,proof,actor)

def restore_check(s,filename,destination,target_settings,key_file=None,actor='local_cli'):
    from jobs import restore
    from manage import initialize
    backup_path(s,filename)
    source_settings=s.db_settings
    if (source_settings['host'].lower(),source_settings['port'],source_settings['database'])==(
            target_settings['host'].lower(),target_settings['port'],target_settings['database']):
        raise ValueError('Source database cannot be the verification destination')
    # Every attempt requires a new folder and an EMPTY DB. The restore routine independently checks both.
    destination=Path(destination).resolve()
    if destination.exists(): raise ValueError('Verification destination must not exist')
    proof={}
    try:
        proof,snapshot=inspect_file(s,filename,key_file)
        restore(backup_path(s,filename),key_file or s.home/'backup.key',destination,target_settings)
        recovered=initialize(destination,restored=True)
        # Compare retained evidence, not just table existence. The original DB is never changed here.
        preserved=('consents','audit','admins','terms_documents','notifications','notification_updates',
                   'terms_revisions','terms_publications','storage_samples','backup_checks','support_exports',
                   'checklist_runs','checklist_entries')
        if filename.endswith('.sffbackup'):
            from stream_backup import compare_restored
            compare_restored(recovered,snapshot)
        else:
            compare_legacy(recovered,snapshot,preserved)
        # Match the final source ciphertext to the exact bytes checked before restore.
        final_proof,_=inspect_file(s,filename,key_file)
        if final_proof!=proof: raise ValueError('Source backup changed during restore check')
        status,code='passed','restored_and_compared'
    except InvalidToken: status,code='failed','authentication_failed'
    except OverflowError: status,code='failed','verifier_size_limit'
    except (ValueError,TypeError,KeyError,DatabaseError,OSError): status,code='failed','restore_check_failed'
    with s.db(True) as db: return store_check(s,db,filename,'restore',status,code,proof,actor)

def compare_legacy(recovered,snapshot,preserved):
    with recovered.db() as db:
        if not table_health(db): raise ValueError('Restored schema not healthy')
        if db.execute('SELECT count(*) FROM sessions').fetchone()[0]: raise ValueError('Restored sessions active')
        if db.execute("SELECT count(*) FROM grants WHERE authorization_status NOT IN ('expired','revoked')").fetchone()[0]: raise ValueError('Restored grants active')
        if db.execute('SELECT count(*) FROM mfa_settings WHERE enabled=1 AND needs_reset=0').fetchone()[0]: raise ValueError('Restored MFA not awaiting review')
        for table in preserved:
            expected=snapshot['tables'].get(table,[])
            actual=db.execute('SELECT * FROM `'+table+'`').fetchall()
            canonical=lambda rows: sorted(json.dumps(dict(r),ensure_ascii=False,sort_keys=True,separators=(',',':')) for r in rows)
            # Legacy notifications acquire a default generation during the additive upgrade.
            if table=='notifications' and snapshot['schema_version']=='2': expected=[dict(r,generation=1) for r in expected]
            if canonical(actual)!=canonical(expected): raise ValueError('Restored retained records differ')
