"""Bounded JSON-lines MySQL snapshots; schema 4 only, legacy Fernet is retained."""
import hashlib,json,os,re
from pathlib import Path
from database import connect,transaction,initialize_schema,Connection,table_health
from security import protect_directory
from stream_encryption import Writer,open_reader
from filesystem_guard import is_link,regular

MAX_LINE=4*1024*1024
SKIP={'sessions','login_limits','launches','contexts','idempotency'}
PRESERVED=('consents','audit','admins','terms_documents','notifications','notification_updates','terms_revisions',
           'terms_publications','storage_samples','backup_checks','support_exports','checklist_runs','checklist_entries')
def encoded(data): return json.dumps(data,ensure_ascii=False,separators=(',',':')).encode()+b'\n'
def schema(): return Path(__file__).parent/'schema.sql'
def file_hash(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as handle:
        while block:=handle.read(1024*1024): digest.update(block)
    return digest.hexdigest()
def info_for(db,table):
    columns=[r['Field'] for r in db.execute('SHOW COLUMNS FROM `'+table+'`').fetchall()]
    indexes=db.execute('SHOW INDEX FROM `'+table+'`').fetchall()
    primary=[r['Column_name'] for r in sorted((r for r in indexes if r['Key_name']=='PRIMARY'),key=lambda r:r['Seq_in_index'])]
    if not primary: raise ValueError('Primary key required')
    return dict(columns=columns,primary=primary)
def rows(db,table,description):
    # Use an unbuffered cursor: Connection.execute intentionally buffers ordinary UI queries.
    cursor=db.raw.cursor(dictionary=True,buffered=False)
    try:
        cursor.execute('SELECT * FROM `'+table+'` ORDER BY '+','.join('`'+c+'`' for c in description['primary']))
        for row in cursor: yield [row[c] for c in description['columns']]
    finally: cursor.close()
def hash_rows(db,table,description):
    digest=hashlib.sha256();count=0
    for row in rows(db,table,description): digest.update(encoded(row));count+=1
    return dict(rows=count,sha256=digest.hexdigest())
def records(path,key):
    with Path(path).open('rb') as raw,open_reader(raw,key) as reader:
        while line:=reader.readline(MAX_LINE+1):
            if len(line)>MAX_LINE or not line.endswith(b'\n'): raise ValueError('Oversized snapshot record')
            yield json.loads(line)
def inspect(path,key):
    from jobs import TABLES
    stream=iter(records(path,key));header=next(stream,None)
    if (not isinstance(header,dict) or set(header)!={'format','schema_version','schema_sha256','tables'}
        or header['format']!='festival-wifi-stream-backup-v1' or header['schema_version']!='4'
        or header['schema_sha256']!=file_hash(schema()) or set(header['tables'])!=set(TABLES)): raise ValueError('Invalid stream snapshot')
    for description in header['tables'].values():
        if (not isinstance(description,dict) or set(description)!={'columns','primary'}
            or any(not isinstance(description[k],list) or not description[k] for k in ('columns','primary'))
            or any(not isinstance(c,str) or not re.fullmatch(r'[a-z_][a-z0-9_]*',c) for k in description for c in description[k])
            or len(set(description['columns']))!=len(description['columns'])
            or not set(description['primary'])<=set(description['columns'])): raise ValueError('Invalid snapshot columns')
    summaries={}
    for table in TABLES:
        if next(stream,None)!={'table':table}: raise ValueError('Invalid table order')
        digest=hashlib.sha256();count=0
        for record in stream:
            if isinstance(record,list):
                if len(record)!=len(header['tables'][table]['columns']) or any(v is not None and type(v) not in (str,int) for v in record): raise ValueError('Invalid row')
                digest.update(encoded(record));count+=1
            else:
                expected=dict(end=table,rows=count,sha256=digest.hexdigest())
                if record!=expected: raise ValueError('Invalid table digest')
                summaries[table]=dict(rows=count,sha256=digest.hexdigest());break
        else: raise ValueError('Truncated snapshot table')
    if next(stream,None)!={'complete':True} or next(stream,None) is not None: raise ValueError('Invalid snapshot end')
    return dict(header=header,summaries=summaries)
def backup_stream_v4_history(s):
    from jobs import TABLES,housekeeping,set_meta
    from app import uid
    if s.config.get('backup_retention_days') is None: raise ValueError('Configure backup policy')
    housekeeping(s);target=s.home/'backups'
    if is_link(target): raise ValueError('Linked backup directory')
    target.mkdir(mode=0o700,exist_ok=True);protect_directory(target)
    name=f'backup-{s.now()}-{uid()}.sffbackup';partial=target/(name+'.partial');key=(s.home/'backup.key').read_bytes()
    with partial.open('xb') as raw:
        writer=Writer(raw,key)
        with s.db() as db:
            if not table_health(db): raise ValueError('Unexpected schema')
            descriptions={table:info_for(db,table) for table in TABLES}
            writer.write(encoded(dict(format='festival-wifi-stream-backup-v1',schema_version='4',schema_sha256=file_hash(schema()),tables=descriptions)))
            for table in TABLES:
                writer.write(encoded(dict(table=table)));digest=hashlib.sha256();count=0
                for row in rows(db,table,descriptions[table]):
                    line=encoded(row)
                    if len(line)>MAX_LINE: raise ValueError('Snapshot record exceeds limit')
                    writer.write(line);digest.update(line);count+=1
                writer.write(encoded(dict(end=table,rows=count,sha256=digest.hexdigest())))
            writer.write(encoded(dict(complete=True)))
        writer.finish();os.fsync(raw.fileno())
    inspect(partial,key);filename=target/name
    os.rename(partial,filename)
    with s.db(True) as db: set_meta(db,'last_backup_at',s.now());s.audit(db,'worker','backup_created')
    return filename
def restore_stream(source,key_path,destination,settings):
    from jobs import secure_new_file,set_meta
    from app import uid
    regular(source);regular(key_path)
    key=Path(key_path).read_bytes();before=file_hash(source);summary=inspect(source,key)
    if file_hash(source)!=before: raise ValueError('Source changed during initial verification')
    destination=Path(destination).resolve()
    if destination.exists(): raise ValueError('Destination exists')
    raw=connect(settings)
    try:
        if Connection(raw).execute('SHOW TABLES').fetchall(): raise ValueError('Restore database not empty')
    finally: raw.close()
    destination.mkdir(mode=0o700);protect_directory(destination)
    secure_new_file(destination/'mysql.json',json.dumps(settings).encode());secure_new_file(destination/'restore.incomplete',b'review required')
    initialize_schema(settings,schema())
    with transaction(settings,True) as db:
        for table,description in summary['header']['tables'].items():
            if info_for(db,table)!=description: raise ValueError('Schema column mismatch')
        db.execute('DELETE FROM meta');table=None
        for record in records(source,key):
            if isinstance(record,dict):
                if 'table' in record: table=record['table']
            elif isinstance(record,list) and table not in SKIP:
                columns=summary['header']['tables'][table]['columns']
                db.execute('INSERT INTO `'+table+'` ('+','.join('`'+c+'`' for c in columns)+') VALUES ('+','.join('?' for _ in columns)+')',record)
        # A second complete authenticated pass above is bound to the inspected file.
        if file_hash(source)!=before: raise ValueError('Source changed during restore')
        db.execute("UPDATE grants SET authorization_status=CASE WHEN authorization_status='revoked' THEN 'revoked' ELSE 'expired' END,observation_state='unknown',revocation_state='failed',row_version=row_version+1")
        db.execute("UPDATE operations SET status='failed',last_error_code='restore_requires_reconciliation'")
        db.execute('UPDATE mfa_settings SET needs_reset=1 WHERE enabled=1');set_meta(db,'restored_requires_review','true')
    (destination/'restore.incomplete').unlink()
    return destination
def compare_restored(recovered,summary):
    with recovered.db() as db:
        if not table_health(db): raise ValueError('Restored schema mismatch')
        for table in PRESERVED:
            if hash_rows(db,table,summary['header']['tables'][table])!=summary['summaries'][table]: raise ValueError('Restored evidence mismatch')
        if db.execute('SELECT count(*) FROM sessions').fetchone()[0]: raise ValueError('Restored session present')
        if db.execute("SELECT count(*) FROM grants WHERE authorization_status NOT IN ('expired','revoked')").fetchone()[0]: raise ValueError('Restored grant active')
        if db.execute('SELECT count(*) FROM mfa_settings WHERE enabled=1 AND needs_reset=0').fetchone()[0]: raise ValueError('Restored MFA active')

def backup_stream(s):
    from workflow_backup import backup_stream as backup_schema5
    return backup_schema5(s)

def inspect_dispatch(path,key):
    # Read only the authenticated first line to select a strict parser; no fallback.
    with Path(path).open('rb') as raw,open_reader(raw,key) as reader:
        header=json.loads(reader.readline(MAX_LINE+1))
    if not isinstance(header,dict):raise ValueError('Object snapshot header required')
    if header.get('format')=='festival-wifi-stream-backup-v2':
        from workflow_backup import inspect as inspect_schema5
        return inspect_schema5(path,key)
    if header.get('format')=='festival-wifi-stream-backup-v1':return inspect(path,key)
    raise ValueError('Unsupported snapshot format')
