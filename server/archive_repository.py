"""Owner-bound archive queues and bounded immutable copies; never delete records."""
import hashlib,json
from app import uid,utc,timestamp
from workflow_common import canonical,sha,policy,validate,API,fail,identifier,encode_cursor
from workflow_generation import require_runtime_ready

CSV_COLUMNS=['id','event_id','terms_version','terms_sha256','policy_version','accepted_at_utc','language','delete_after']
ITEM_KEYS=['consent_id','source_seq','event_id','terms_version','terms_sha256','policy_version','accepted_at_utc','language','delete_after','deadline_scope']

def owner_allowed(db,owner):
    row=db.execute('SELECT enabled,role FROM admins WHERE id=?',(owner,)).fetchone()
    if not row or not row['enabled'] or row['role'] not in ('records','settings'):fail('permission_denied',403)

def filters(s,value):
    validate(API['components']['schemas']['ArchiveFilters'],value)
    start,end=timestamp(value['accepted_start_utc']),timestamp(value['accepted_end_utc'])
    if not 0<end-start<=policy(s)['export_range_seconds']:fail('archive_range_invalid',400)
    return value

def predicate(values,as_of):
    sql='event_id=? AND accepted_at_utc>=? AND accepted_at_utc<? AND accepted_at_utc<=?'
    args=[values['event_id'],values['accepted_start_utc'],values['accepted_end_utc'],utc(as_of)]
    if values['language'] is not None:sql+=' AND language=?';args.append(values['language'])
    if values['deadline_scope']!='all':
        sql+=' AND delete_after'+('>' if values['deadline_scope']=='within_processing_deadline' else '<=')+'?';args.append(as_of)
    return sql,args

def archive_event(s,db,export_id,kind,actor_type,actor=None,evidence=None,page_start=None,page_end=None,page_sha=None):
    db.execute('INSERT INTO consent_archive_events VALUES (?,?,?,?,?,?,?,?,?,?,?)',
               (uid(),export_id,kind,actor_type,actor,s.now(),uid(),page_start,page_end,page_sha,evidence))

def load(db,owner,export_id):
    row=db.execute('SELECT * FROM consent_archive_exports WHERE id=? AND owner_id=?',(identifier(export_id),owner)).fetchone()
    if not row:fail('export_not_found',404)
    return row

def current_generation(s,db,row):
    generation=require_runtime_ready(s,db)
    queued=db.execute("SELECT evidence_code FROM consent_archive_events WHERE export_id=? AND kind='queued' ORDER BY created_at,id LIMIT 1",(row['id'],)).fetchone()
    return bool(queued and queued['evidence_code']=='g:'+generation)

def queue(s,db,owner,data):
    owner_allowed(db,owner);generation=require_runtime_ready(s,db);values=filters(s,data['filters']);fingerprint=sha(canonical(values))
    if db.execute("SELECT 1 FROM consent_archive_exports WHERE owner_id=? AND state IN ('queued','preparing') LIMIT 1",(owner,)).fetchone():fail('export_already_running')
    retry=data['retry_of']
    if retry:
        source=load(db,owner,retry)
        if source['state']!='failed' or source['filters_sha256']!=fingerprint or db.execute('SELECT 1 FROM consent_archive_exports WHERE retry_of_id=? LIMIT 1',(retry,)).fetchone():fail('retry_source_invalid')
    export_id=uid();now=s.now()
    db.execute('INSERT INTO consent_archive_exports VALUES (?,?,?,?,?,?,?,1,?,NULL)',(export_id,owner,canonical(values).decode(),fingerprint,now,now,'queued',retry))
    archive_event(s,db,export_id,'queued','admin',owner,'g:'+generation);s.audit(db,owner,'consent_archive_queued',export_id)
    return dict(export_id=export_id,state='queued',as_of_utc=utc(now),status_path='/v1/admin/consent-archive-exports/'+export_id)

def snapshot_context(job,snapshot):return dict(export_id=job['id'],snapshot_id=snapshot['id'],rows_sha256=snapshot['rows_sha256'],filters_sha256=job['filters_sha256'])

def ready_evidence(s,db,row,snapshot,current=None):
    if not snapshot or row['state']!='ready' or snapshot['state']!='ready':return False
    if (current_generation(s,db,row) if current is None else current):return True
    generation=require_runtime_ready(s,db)
    meta=db.execute('SELECT value FROM meta WHERE name=?',('workflow5_export_release_'+row['id'],)).fetchone()
    if not meta:return False
    try:
        from workflow_common import read_private,strict_json
        value=json.loads(meta['value'])
        receipt=read_private(s.home,'restore-history/'+generation,'export-'+row['id']+'.json')
        proof=strict_json(receipt)
        return value.get('generation')==generation and value.get('rows_sha256')==snapshot['rows_sha256'] and value.get('receipt_sha256')==sha(receipt) and proof.get('export_id')==row['id'] and proof.get('snapshot_id')==snapshot['id'] and proof.get('rows_sha256')==snapshot['rows_sha256']
    except (OSError,ValueError,TypeError,KeyError,__import__('app').ApiError):return False

def view(s,db,row,snapshot=False,generation_matches=None):
    if snapshot is False:snapshot=db.execute('SELECT * FROM consent_archive_snapshots WHERE export_id=?',(row['id'],)).fetchone()
    active=current_generation(s,db,row) if generation_matches is None else generation_matches
    ready=ready_evidence(s,db,row,snapshot,current=active)
    effective=row['state'] if active or ready else 'recovery_required';summary=None
    if ready:
        summary=dict(snapshot_id=snapshot['id'],snapshot_started_at_utc=utc(snapshot['snapshot_started_at']),prepared_at_utc=utc(snapshot['prepared_at']),
                     total_count=snapshot['item_count'],rows_sha256=snapshot['rows_sha256'],first_page_cursor=encode_cursor(s,'archive-content',row['owner_id'],0,snapshot_context(row,snapshot)),csv_columns=CSV_COLUMNS)
    values=json.loads(row['filters_json']) if isinstance(row['filters_json'],(str,bytes)) else row['filters_json']
    return dict(export_id=row['id'],owner_id=row['owner_id'],filters=values,filters_sha256=row['filters_sha256'],as_of_utc=utc(row['as_of']),created_at_utc=utc(row['created_at']),
                state=row['state'],version=row['row_version'],retry_of=row['retry_of_id'],error_code=row['error_code'],snapshot=summary,effective_state=effective)

def item_data(row,as_of):
    return dict(consent_id=row['id'],source_seq=row['seq'],event_id=row['event_id'],terms_version=row['terms_version'],terms_sha256=row['terms_sha256'],
                policy_version=row['policy_version'],accepted_at_utc=row['accepted_at_utc'],language=row['language'],delete_after=row['delete_after'],
                deadline_scope='within_processing_deadline' if row['delete_after']>as_of else 'processing_deadline_elapsed')

def item_hash(item,ordinal):return sha(canonical({'ordinal':ordinal,**{key:item[key] for key in ITEM_KEYS}}))

def seal(db,snapshot_id):
    digest=hashlib.sha256();count=0
    cursor=db.raw.cursor(dictionary=True,buffered=False)
    try:
        cursor.execute('SELECT * FROM consent_archive_items WHERE snapshot_id=%s ORDER BY ordinal',(snapshot_id,))
        for row in cursor:
            count+=1
            if row['ordinal']!=count or item_hash(row,count)!=row['row_sha256']:raise ValueError('Copy integrity differs')
            digest.update(row['row_sha256'].encode('ascii')+b'\n')
    finally:cursor.close()
    return count,digest.hexdigest()

def mark_failed(s,export_id,code,allow_old_generation=False,actor_type='worker'):
    with s.db(True) as db:
        row=db.execute('SELECT * FROM consent_archive_exports WHERE id=?',(export_id,)).fetchone()
        if not row or row['state'] not in ('queued','preparing'):return
        if not allow_old_generation and not current_generation(s,db,row):return
        db.execute("UPDATE consent_archive_exports SET state='failed',row_version=row_version+1,error_code=? WHERE id=?",(code,export_id))
        db.execute("UPDATE consent_archive_snapshots SET state='failed',prepared_at=?,item_count=NULL,rows_sha256=NULL,error_code=? WHERE export_id=? AND state='preparing'",(s.now(),code,export_id))
        archive_event(s,db,export_id,'failed',actor_type,evidence=code);s.audit(db,'local_cli' if actor_type=='recovery_cli' else 'worker','consent_archive_failed',export_id)

def prepare_next(s):
    policy(s)
    with s.db(True) as db:
        generation=require_runtime_ready(s,db)
        # Old preparing work is never continued. The direct worker lock makes one consumer.
        interrupted=db.execute("SELECT e.id FROM consent_archive_exports e JOIN consent_archive_events v ON v.export_id=e.id AND v.kind='queued' WHERE e.state='preparing' AND v.evidence_code=? ORDER BY e.created_at,e.id LIMIT 1",('g:'+generation,)).fetchone()
        queued=db.execute("SELECT e.* FROM consent_archive_exports e JOIN consent_archive_events v ON v.export_id=e.id AND v.kind='queued' WHERE e.state='queued' AND v.evidence_code=? ORDER BY e.created_at,e.id LIMIT 1",('g:'+generation,)).fetchone()
        if interrupted:job_id=interrupted['id'];job=None
        elif queued:
            job=dict(queued);job_id=job['id'];snapshot_id=uid()
            db.execute("UPDATE consent_archive_exports SET state='preparing',row_version=row_version+1 WHERE id=?",(job_id,))
            db.execute("INSERT INTO consent_archive_snapshots VALUES (?,?,?,NULL,'preparing',NULL,NULL,NULL)",(snapshot_id,job_id,s.now()))
            archive_event(s,db,job_id,'preparing','worker',evidence='snapshot_started')
        else:return None
    if job is None:mark_failed(s,job_id,'preparation_interrupted');return job_id
    try:
        values=json.loads(job['filters_json']) if isinstance(job['filters_json'],(str,bytes)) else job['filters_json']
        filters(s,values);where,params=predicate(values,job['as_of']);after=0;ordinal=0;maximum=policy(s)['export_row_limit']
        # One source snapshot throughout all batches, separate short write transactions.
        with s.db() as source_db:
            while True:
                rows=source_db.execute('SELECT * FROM consents WHERE '+where+' AND seq>? ORDER BY seq LIMIT 1000',params+[after]).fetchall()
                if not rows:break
                if ordinal+len(rows)>maximum:mark_failed(s,job_id,'row_limit_exceeded');return job_id
                with s.db(True) as db:
                    owner_allowed(db,job['owner_id']);fresh=load(db,job['owner_id'],job_id)
                    if fresh['state']!='preparing' or not current_generation(s,db,fresh):raise ValueError('Preparation state differs')
                    batch=[]
                    for row in rows:
                        ordinal+=1;data=item_data(row,job['as_of']);digest=item_hash(data,ordinal)
                        batch.append([snapshot_id,ordinal,*[data[key] for key in ITEM_KEYS],digest])
                    db.executemany('INSERT INTO consent_archive_items VALUES ('+','.join('?' for _ in range(13))+')',batch)
                    after=rows[-1]['seq']
        with s.db() as db:count,digest=seal(db,snapshot_id)
        if count!=ordinal:raise ValueError('Copy count differs')
        with s.db(True) as db:
            owner_allowed(db,job['owner_id']);fresh=load(db,job['owner_id'],job_id)
            if fresh['state']!='preparing' or not current_generation(s,db,fresh):raise ValueError('Preparation state differs')
            db.execute("UPDATE consent_archive_snapshots SET state='ready',prepared_at=?,item_count=?,rows_sha256=? WHERE export_id=? AND state='preparing'",(s.now(),count,digest,job_id))
            db.execute("UPDATE consent_archive_exports SET state='ready',row_version=row_version+1 WHERE id=?",(job_id,))
            archive_event(s,db,job_id,'ready','worker',evidence='copy_sealed');s.audit(db,'worker','consent_archive_ready',job_id)
    except (OSError,ValueError,TypeError,KeyError,__import__('app').ApiError):mark_failed(s,job_id,'source_read_interrupted')
    except __import__('database').DatabaseError:
        # If this also fails, preparing is retained and the next worker reports interruption.
        mark_failed(s,job_id,'storage_unavailable')
    return job_id
