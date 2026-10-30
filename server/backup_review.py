"""Record measured backup checks. No plaintext dump or overwrite of an existing database."""
from pathlib import Path
import stat
import uuid
from cryptography.fernet import InvalidToken
from operations import BACKUP_NAME
from filesystem_guard import is_link,file_hash

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
    from workflow_backup import inspect
    path=backup_path(s,filename)
    info=path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode): raise ValueError('Not a regular file')
    before_hash=file_hash(path)
    snapshot=inspect(path,Path(key_file or s.home/'backup.key').read_bytes())
    if file_hash(path)!=before_hash: raise ValueError('Source changed during verification')
    proof=dict(ciphertext_sha256=before_hash,file_bytes=info.st_size,file_mtime_ns=info.st_mtime_ns)
    after=path.stat(follow_symlinks=False)
    if (info.st_size,info.st_mtime_ns)!=(after.st_size,after.st_mtime_ns): raise ValueError('File changed')
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
