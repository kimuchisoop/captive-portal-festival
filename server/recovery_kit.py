"""Encrypted recovery evidence with a separately generated key; never an in-place restore."""
from contextlib import contextmanager,ExitStack
import hashlib,io,json,os,stat,tarfile
from pathlib import Path,PurePosixPath
from cryptography.fernet import Fernet
from jobs import secure_new_file
from security import protect_directory
from stream_encryption import Writer,open_reader
from stream_backup import backup_stream,file_hash
from filesystem_guard import is_link,regular

ROOT_FILES={'config.json','terms.ja.txt','terms.en.txt','device-profile.json','session.key','backup.key','mfa.key'}
DIRECTORIES={'backups','runtime','support-reports','diagnostics','configuration-history','configuration-imports','restore-history','migration-history'}

@contextmanager
def stopped(home):
    if is_link(home/'runtime'): raise ValueError('Linked runtime directory')
    current=home/'runtime/current.json'
    if is_link(current):raise ValueError('Linked runtime status')
    if current.exists():regular(current)
    if current.exists() and json.loads(current.read_text())['state']=='running': raise ValueError('Stop app and worker first')
    runtime=home/'runtime';runtime.mkdir(exist_ok=True);protect_directory(runtime)
    path=runtime/'supervisor.lock'
    if is_link(path):raise ValueError('Linked supervisor lock')
    if path.exists():regular(path)
    with path.open('a+b') as handle:
        if os.fstat(handle.fileno()).st_size==0:handle.write(b'1');handle.flush()
        handle.seek(0);locked=False
        try:
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
            locked=True
            from runtime_guard import owned_runtime
            with ExitStack() as stack:
                stack.enter_context(owned_runtime(home,'app'));stack.enter_context(owned_runtime(home,'worker'));yield
        finally:
            if locked and os.name=='nt': handle.seek(0);msvcrt.locking(handle.fileno(),msvcrt.LK_UNLCK,1)

def safe_name(name):
    if not isinstance(name,str) or '\\' in name or ':' in name or any(ord(c)<32 for c in name): raise ValueError('Invalid member path')
    path=PurePosixPath(name)
    if path.is_absolute() or name!=path.as_posix() or any(part in ('','..','.') for part in path.parts): raise ValueError('Invalid member path')
    reserved={'con','prn','aux','nul'}|{'com'+str(i) for i in range(1,10)}|{'lpt'+str(i) for i in range(1,10)}
    if any(part.endswith(('.', ' ')) or part.split('.')[0].casefold() in reserved for part in path.parts): raise ValueError('Ambiguous Windows member name')
    if name not in ('manifest.json','database.sffbackup') and not name.startswith('files/'): raise ValueError('Unknown archive root')
    return path

def source_files(home):
    found=[]
    for name in ROOT_FILES:
        path=home/name
        if path.exists(): found.append(path)
    for name in DIRECTORIES:
        parent=home/name
        if is_link(parent): raise ValueError('Linked source directory')
        if not parent.exists(): continue
        for directory,dirs,files in os.walk(parent,followlinks=False):
            if any(is_link(Path(directory)/d) for d in dirs): raise ValueError('Linked source directory')
            for filename in files:
                if name=='runtime' and not filename.endswith('.log'): continue
                found.append(Path(directory)/filename)
    for path in found:
        if is_link(path) or not stat.S_ISREG(path.stat(follow_symlinks=False).st_mode): raise ValueError('Nonregular source file')
    return sorted(found)

def consume(path,key,destination=None):
    seen={};canonical_names=set();manifest=None
    with Path(path).open('rb') as raw,open_reader(raw,key) as decrypted:
        with tarfile.open(fileobj=decrypted,mode='r|',bufsize=512) as archive:
            for member in archive:
                safe_name(member.name)
                canonical=member.name.casefold()
                if manifest is not None or canonical in canonical_names or not member.isfile() or member.issparse() or member.size<0: raise ValueError('Invalid archive member')
                canonical_names.add(canonical)
                stream=archive.extractfile(member)
                if member.name=='manifest.json':
                    if member.size>4*1024*1024: raise ValueError('Manifest too large')
                    manifest=json.loads(stream.read());continue
                digest=hashlib.sha256();size=0;output=None
                if destination is not None:
                    target=destination.joinpath(*PurePosixPath(member.name).parts)
                    if not target.resolve().is_relative_to(destination): raise ValueError('Path escapes destination')
                    target.parent.mkdir(parents=True,exist_ok=True);output=target.open('xb')
                try:
                    while block:=stream.read(1024*1024):
                        digest.update(block);size+=len(block)
                        if output: output.write(block)
                    if output: output.flush();os.fsync(output.fileno())
                finally:
                    if output: output.close()
                if size!=member.size: raise ValueError('Truncated archive member')
                seen[member.name]=dict(bytes=size,sha256=digest.hexdigest())
        # tar EOF is not encrypted EOF: consume padding and authenticate the terminal frame.
        while block:=decrypted.read(1024*1024):
            if any(block): raise ValueError('Data after tar EOF')
    if (not isinstance(manifest,dict) or manifest.get('format') not in ('festival-recovery-kit-v1','festival-recovery-kit-v2')
        or manifest.get('files')!=seen or 'database.sffbackup' not in seen
        or any('files/'+name not in seen for name in ('config.json','backup.key','mfa.key','session.key','terms.ja.txt','terms.en.txt'))): raise ValueError('Incomplete recovery kit')
    return manifest

def create_kit(s,output,key_directory):
    from app import uid
    output=Path(output).resolve();key_directory=Path(key_directory).resolve()
    if output.exists() or output.is_relative_to(s.home) or key_directory.is_relative_to(s.home): raise ValueError('Use NEW locations outside the data directory')
    if key_directory==output.parent or key_directory.is_relative_to(output.parent): raise ValueError('Key directory must be separate from archive directory')
    if not output.parent.is_dir(): raise ValueError('Archive parent must exist')
    with stopped(s.home):
        snapshot=backup_stream(s)
        files=[p for p in source_files(s.home) if p!=snapshot]
        key_directory.mkdir(mode=0o700,exist_ok=False);protect_directory(key_directory)
        key=Fernet.generate_key();secure_new_file(key_directory/'recovery.key',key)
        # Both ciphertext and retained partial ciphertext use private OS permissions.
        partial=output.with_name(output.name+'.partial');inventory={}
        with partial.open('xb') as raw:
            writer=Writer(raw,key)
            with tarfile.open(fileobj=writer,mode='w|',format=tarfile.PAX_FORMAT) as archive:
                for name,path in [('database.sffbackup',snapshot)]+[('files/'+p.relative_to(s.home).as_posix(),p) for p in files]:
                    safe_name(name);before=path.stat(follow_symlinks=False)
                    if is_link(path) or not stat.S_ISREG(before.st_mode): raise ValueError('Source changed')
                    digest=file_hash(path);info=tarfile.TarInfo(name);info.size=before.st_size;info.mode=0o600;info.mtime=int(before.st_mtime)
                    with path.open('rb') as handle: archive.addfile(info,handle)
                    after=path.stat(follow_symlinks=False)
                    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns) or file_hash(path)!=digest: raise ValueError('Source changed during copy')
                    inventory[name]=dict(bytes=before.st_size,sha256=digest)
                manifest=dict(format='festival-recovery-kit-v2',created_at=s.now(),files=inventory,
                              exclusions=['mysql.json','QA credentials','runtime control files'],schema_version=5)
                data=json.dumps(manifest,ensure_ascii=False).encode();info=tarfile.TarInfo('manifest.json');info.size=len(data);info.mode=0o600
                archive.addfile(info,io.BytesIO(data))
            writer.finish();os.fsync(raw.fileno())
        consume(partial,key);os.rename(partial,output)
        with s.db(True) as db: s.audit(db,'local_cli','recovery_kit_created')
    return dict(status='verified',files=len(inventory),ciphertext_bytes=output.stat().st_size,ciphertext_sha256=file_hash(output),key_stored_separately=True)

def restore_kit(source,key_path,destination,settings):
    from app import uid
    from stream_backup import restore_stream,inspect,compare_restored
    from manage import initialize
    destination=Path(destination).resolve()
    if destination.exists(): raise ValueError('Restore destination must not exist')
    from filesystem_guard import regular
    regular(source);regular(key_path)
    key=Path(key_path).read_bytes();proof=file_hash(source);consume(source,key)
    if file_hash(source)!=proof: raise ValueError('Recovery source changed during verification')
    evidence=destination.with_name(destination.name+'-evidence-'+uid());evidence.mkdir(mode=0o700);protect_directory(evidence)
    secure_new_file(evidence/'recovery.incomplete',b'restore pending')
    manifest=consume(source,key,evidence)
    if file_hash(source)!=proof: raise ValueError('Recovery source changed')
    snapshot=evidence/'database.sffbackup';backup_key=evidence/'files/backup.key'
    summary=inspect(snapshot,backup_key.read_bytes());restore_stream(snapshot,backup_key,destination,settings)
    recovered=initialize(destination,restored=True);compare_restored(recovered,summary)
    secure_new_file(evidence/'restore-result.json',json.dumps(dict(status='verified',files=len(manifest['files']),database_schema=4,intake_enabled=False,original_files_preserved=True)).encode())
    (evidence/'recovery.incomplete').unlink()
    return dict(status='verified',evidence_directory=str(evidence),database_schema=4,files=len(manifest['files']),intake_enabled=False,ap_adapter='disconnected')
