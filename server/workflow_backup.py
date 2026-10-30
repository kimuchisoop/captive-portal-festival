"""Typed, bounded schema-five snapshots on the existing authenticated container."""
from pathlib import Path
import hashlib,json,os,re,shutil
from app import ROOT,uid,utc
from database import transaction,initialize_schema
from stream_encryption import Writer,open_reader
from filesystem_guard import regular,is_link,file_hash
from security import protect_directory
from jobs import secure_new_file,set_meta
from workflow_common import canonical,strict_json,sha,private_dir,read_private,validate,API
from workflow_database import CONTRACT,TABLES,verify_contract,maintenance_settings

MAX_LINE=4*1024*1024
SKIP={'sessions','login_limits','launches','contexts','idempotency'}
CONTRACT_SHA=sha(canonical(CONTRACT))
INTEGER=re.compile(r'^(?:0|-[1-9][0-9]*|[1-9][0-9]*)$')

def cell(column,value,decode=False):
    if value is None:
        if not column['nullable']:raise ValueError('Unexpected SQL NULL')
        return None
    codec=column['codec']
    if codec in ('i64-decimal','u64-decimal'):
        if decode:
            if not isinstance(value,str) or not INTEGER.fullmatch(value):raise ValueError('Noncanonical integer')
        elif type(value) is not int:raise ValueError('Unexpected SQL integer')
        number=int(value);low,high=(-(2**63),2**63-1) if codec=='i64-decimal' else (0,2**64-1)
        if not low<=number<=high:raise ValueError('Integer out of range')
        return number if decode else str(number)
    if codec=='utf8':
        if not isinstance(value,str):raise ValueError('Unexpected SQL text')
        value.encode('utf-8');return value
    if codec=='json-object-v1':
        if isinstance(value,(str,bytes)):parsed=strict_json(value.encode('utf-8') if isinstance(value,str) else value)
        elif not decode and isinstance(value,dict):parsed=value
        else:raise ValueError('Unexpected SQL JSON')
        try:validate(API['components']['schemas']['ArchiveFilters' if column['name']=='filters_json' else 'EventValues'],parsed)
        except __import__('app').ApiError as error:raise ValueError('Invalid typed JSON cell') from error
        text=canonical(parsed).decode()
        if decode and text!=value:raise ValueError('Noncanonical JSON cell')
        return text
    raise ValueError('Unknown codec')

def row_line(table,row):return canonical(dict(kind='row',cells=[cell(column,row[column['name']]) for column in table['columns']]))+b'\n'

def database_rows(db,table):
    cursor=db.raw.cursor(dictionary=True,buffered=False)
    try:
        cursor.execute('SELECT * FROM `'+table['name']+'` ORDER BY '+','.join('`'+name+'`' for name in table['primary']))
        yield from cursor
    finally:cursor.close()

def table_digest(db,table):
    digest=hashlib.sha256();count=0
    for row in database_rows(db,table):digest.update(row_line(table,row));count+=1
    return dict(rows=str(count),sha256=digest.hexdigest())

def records(path,key):
    with Path(path).open('rb') as raw,open_reader(raw,key) as reader:
        while line:=reader.readline(MAX_LINE+1):
            if len(line)>MAX_LINE or not line.endswith(b'\n'):raise ValueError('Oversized or incomplete record')
            value=strict_json(line)
            if not isinstance(value,dict):raise ValueError('Object record required')
            if canonical(value)+b'\n'!=line:raise ValueError('Noncanonical record')
            yield value,line

def inspect(path,key):
    stream=iter(records(path,key));header,_=next(stream,({},b''))
    if set(header)!={'kind','format','schema_version','codec_version','contract_sha256','schema_sha256','backup_id','created_at_utc','tables'} or header['kind']!='header' or header['format']!='festival-wifi-stream-backup-v2' or header['schema_version']!='5' or header['codec_version']!='1' or header['contract_sha256']!=CONTRACT_SHA or header['schema_sha256']!=file_hash(ROOT/'schema-v5.sql') or header['tables']!=list(TABLES):raise ValueError('Invalid typed header')
    __import__('workflow_common').identifier(header['backup_id'])
    if utc(__import__('app').timestamp(header['created_at_utc']))!=header['created_at_utc']:raise ValueError('Invalid backup time')
    summaries={};total=0;ends=hashlib.sha256()
    for table in CONTRACT['tables']:
        begin,_=next(stream,({},b''))
        if begin!={'kind':'table_begin','table':table['name']}:raise ValueError('Invalid table order')
        count=0;digest=hashlib.sha256();previous=None
        for value,line in stream:
            if value.get('kind')!='row':break
            if set(value)!={'kind','cells'} or not isinstance(value['cells'],list) or len(value['cells'])!=len(table['columns']):raise ValueError('Invalid row')
            decoded={column['name']:cell(column,item,True) for column,item in zip(table['columns'],value['cells'])}
            key=tuple(decoded[name] for name in table['primary'])
            if previous is not None and key<=previous:raise ValueError('Primary key order differs')
            previous=key;count+=1;digest.update(line)
        else:raise ValueError('Truncated table')
        if value!=dict(kind='table_end',table=table['name'],rows=str(count),sha256=digest.hexdigest()):raise ValueError('Table digest differs')
        summaries[table['name']]=dict(rows=str(count),sha256=digest.hexdigest());total+=count;ends.update(line)
    end,_=next(stream,({},b''))
    if end!=dict(kind='complete',backup_id=header['backup_id'],tables_count='31',total_rows=str(total),tables_sha256=ends.hexdigest()) or next(stream,None) is not None:raise ValueError('Invalid complete marker')
    return dict(header=header,summaries=summaries)

def backup_stream(s):
    from workflow_generation import require_runtime_ready
    if s.config.get('backup_retention_days') is None:raise ValueError('Configure backup policy')
    directory=private_dir(s.home,'backups');filename=f'backup-{s.now()}-{uid()}.sffbackup';partial=directory/(filename+'.partial')
    key=read_private(s.home,'.','backup.key');backup_id=uid()
    with partial.open('xb') as raw:
        protect_directory(directory);writer=Writer(raw,key)
        def emit(value):
            line=canonical(value)+b'\n'
            if len(line)>MAX_LINE:raise ValueError('Snapshot row exceeds limit')
            writer.write(line);return line
        with s.db() as db:
            require_runtime_ready(s,db);verify_contract(db)
            emit(dict(kind='header',format='festival-wifi-stream-backup-v2',schema_version='5',codec_version='1',contract_sha256=CONTRACT_SHA,schema_sha256=file_hash(ROOT/'schema-v5.sql'),backup_id=backup_id,created_at_utc=utc(s.now()),tables=list(TABLES)))
            total=0;ends=hashlib.sha256()
            for table in CONTRACT['tables']:
                emit(dict(kind='table_begin',table=table['name']));digest=hashlib.sha256();count=0
                for row in database_rows(db,table):
                    line=row_line(table,row)
                    if len(line)>MAX_LINE:raise ValueError('Snapshot row exceeds limit')
                    writer.write(line);digest.update(line);count+=1
                ends.update(emit(dict(kind='table_end',table=table['name'],rows=str(count),sha256=digest.hexdigest())));total+=count
            emit(dict(kind='complete',backup_id=backup_id,tables_count='31',total_rows=str(total),tables_sha256=ends.hexdigest()))
        writer.finish();os.fsync(raw.fileno())
    inspect(partial,key);destination=directory/filename
    if destination.exists():raise ValueError('Backup destination exists')
    os.rename(partial,destination)
    with s.db(True) as db:set_meta(db,'last_backup_at',s.now());s.audit(db,'worker','backup_created',backup_id)
    return destination

def restore(source,key_file,destination,runtime_settings,maintenance_file,evidence_home=None):
    from cryptography.fernet import Fernet
    from workflow_generation import create_generation
    regular(source);regular(key_file);key=Path(key_file).read_bytes();source_sha=file_hash(source);summary=inspect(source,key)
    maintenance=maintenance_settings(maintenance_file,runtime_settings);destination=Path(destination).resolve()
    if destination.exists():raise ValueError('Use a NEW recovery directory')
    destination.mkdir(mode=0o700);protect_directory(destination);restore_id=uid()
    secure_new_file(destination/'restore.incomplete',canonical(dict(restore_id=restore_id,source_sha256=source_sha)))
    initialize_schema(maintenance,ROOT/'schema-v5.sql')
    with transaction(maintenance,True) as db:
        table=None
        for record,_ in records(source,key):
            if record['kind']=='table_begin':table=record['table']
            elif record['kind']=='row' and table not in SKIP:
                description=TABLES[table];values=[cell(column,value,True) for column,value in zip(description['columns'],record['cells'])]
                if table=='consent_archive_exports':values[[c['name'] for c in description['columns']].index('retry_of_id')]=None
                db.execute('INSERT INTO `'+table+'` ('+','.join('`'+c['name']+'`' for c in description['columns'])+') VALUES ('+','.join('?' for _ in values)+')',values)
        for record,_ in records(source,key):
            if record['kind']=='table_begin':table=record['table']
            elif record['kind']=='row' and table=='consent_archive_exports':
                decoded={c['name']:cell(c,v,True) for c,v in zip(TABLES[table]['columns'],record['cells'])}
                if decoded['retry_of_id']:
                    parent=db.execute('SELECT owner_id,filters_sha256 FROM consent_archive_exports WHERE id=?',(decoded['retry_of_id'],)).fetchone()
                    if not parent or decoded['id']==decoded['retry_of_id'] or (parent['owner_id'],parent['filters_sha256'])!=(decoded['owner_id'],decoded['filters_sha256']):raise ValueError('Invalid retry parent')
                    db.execute('UPDATE consent_archive_exports SET retry_of_id=? WHERE id=?',(decoded['retry_of_id'],decoded['id']))
        # Detect cycles without deleting or repairing historical edges.
        graph={r['id']:r['retry_of_id'] for r in db.execute('SELECT id,retry_of_id FROM consent_archive_exports').fetchall()}
        checked=set()
        for node in graph:
            visiting=set();current=node
            while current and current not in checked:
                if current in visiting:raise ValueError('Retry cycle')
                visiting.add(current);current=graph[current]
            checked.update(visiting)
        raw_results={}
        for name,description in TABLES.items():
            if name in SKIP:
                if db.execute('SELECT count(*) FROM `'+name+'`').fetchone()[0]:raise ValueError('Excluded credential rows present')
            else:
                raw_results[name]=table_digest(db,description)
                if raw_results[name]!=summary['summaries'][name]:raise ValueError('Raw restored evidence differs')
        if file_hash(source)!=source_sha:raise ValueError('Encrypted source changed')
        safety_changes={}
        safety_changes['grants']=db.execute("UPDATE grants SET authorization_status=CASE WHEN authorization_status='revoked' THEN 'revoked' ELSE 'expired' END,observation_state='unknown',revocation_state='failed',row_version=row_version+1").rowcount
        safety_changes['operations']=db.execute("UPDATE operations SET status='failed',last_error_code='restore_requires_reconciliation'").rowcount
        safety_changes['mfa_settings']=db.execute('UPDATE mfa_settings SET needs_reset=1 WHERE enabled=1').rowcount
        generation=create_generation(db,__import__('time').time_ns()//10**9,'restored',restore_id)
        now=__import__('time').time_ns()//10**9
        db.execute('INSERT INTO audit VALUES (?,?,?,?,?,?)',(uid(),'local_cli','schema5_restored',restore_id,now,now+86400))
    config=strict_json((Path(evidence_home)/'config.json').read_bytes()) if evidence_home else strict_json((ROOT/'config.example.json').read_bytes())
    config.update(local_intake_enabled=False,production_enabled=False,automatic_deletion_enabled=False,backup_format='stream-v2')
    if isinstance(config.get('workflow_policy'),dict):config['workflow_policy']['approved']=False
    secure_new_file(destination/'config.json',canonical(config));secure_new_file(destination/'mysql.json',canonical(runtime_settings))
    for name,value in [('session.key',os.urandom(32)),('backup.key',Fernet.generate_key()),('mfa.key',Fernet.generate_key())]:secure_new_file(destination/name,value)
    for language in ('ja','en'):
        source_term=Path(evidence_home)/('terms.'+language+'.txt') if evidence_home else ROOT/('terms.'+language+'.txt')
        regular(source_term);secure_new_file(destination/source_term.name,source_term.read_bytes())
    if evidence_home:
        from recovery_kit import source_files
        for original in source_files(Path(evidence_home)):
            relative=original.relative_to(evidence_home)
            if relative.parts[0] in ('configuration-history','configuration-imports','restore-history','migration-history','runtime','support-reports','diagnostics','backups'):
                final=destination/relative;final.parent.mkdir(parents=True,exist_ok=True);protect_directory(final.parent)
                with original.open('rb') as source_file,final.open('xb') as target_file:
                    before=os.fstat(source_file.fileno())
                    while block:=source_file.read(1024*1024):target_file.write(block)
                    target_file.flush();os.fsync(target_file.fileno());after=os.fstat(source_file.fileno())
                    if (before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns):raise ValueError('Recovery evidence changed')
    history=private_dir(destination,'restore-history')/restore_id;history.mkdir();protect_directory(history)
    secure_new_file(history/'report.json',canonical(dict(restore_id=restore_id,generation=generation,source_sha256=source_sha,raw_verified=True,preserved_tables=raw_results,excluded_tables=sorted(SKIP),safety_changes=safety_changes,intake_enabled=False,operator_message='復旧後の確認が必要です。サーバー担当による明示解除まで起動しないでください。')))
    return dict(restored=True,requires_manual_release=True,restore_id=restore_id,generation=generation,schema_version=5,records_preserved=True)
