"""Private preview, queue, status and fixed-copy CSV pages for the current owner."""
import csv,io,json
from flask import g,jsonify,request,make_response
from app import utc
from workflow_common import query,request_value,policy,encode_cursor,decode_cursor,page,identifier,fail,sha
from workflow_generation import require_runtime_ready
from workflow_routes import limit_value
import archive_repository as archives

def public_row(row,as_of=None):
    return dict(id=row.get('consent_id',row.get('id')),event_id=row['event_id'],terms_version=row['terms_version'],terms_sha256=row['terms_sha256'],policy_version=row['policy_version'],
                accepted_at_utc=row['accepted_at_utc'],language=row['language'],delete_after=row['delete_after'],
                deadline_scope=row.get('deadline_scope') or ('within_processing_deadline' if row['delete_after']>as_of else 'processing_deadline_elapsed'))

def register(app,s,auth):
    @app.get('/v1/admin/consent-archives')
    @auth('admin','records')
    def search():
        args=query(request.args,('event_id','accepted_start_utc','accepted_end_utc','language','deadline_scope','cursor','limit'))
        values={key:args.get(key) for key in ('event_id','accepted_start_utc','accepted_end_utc','language','deadline_scope')}
        if values['language']=='':values['language']=None
        archives.filters(s,values);after=0;as_of=s.now();expires=None;owner=g.session['owner_id'];limit=limit_value(args)
        if args.get('cursor'):
            position,expires=decode_cursor(s,args['cursor'],'archive-search',owner,values)
            if not isinstance(position,list) or len(position)!=2 or any(type(v) is not int or v<0 for v in position) or position[1]>s.now():fail('cursor_invalid',400)
            after,as_of=position
        where,params=archives.predicate(values,as_of)
        with s.db() as db:
            rows=db.execute('SELECT * FROM consents WHERE '+where+' AND seq>? ORDER BY seq LIMIT ?',params+[after,limit+1]).fetchall()
        cursor=encode_cursor(s,'archive-search',owner,[rows[limit-1]['seq'],as_of],values,expires) if len(rows)>limit else None
        return jsonify(items=[public_row(row,as_of) for row in rows[:limit]],next_cursor=cursor,as_of_utc=utc(as_of),target_fixed=False)

    @app.post('/v1/admin/consent-archive-exports')
    @auth('admin','records')
    def enqueue():
        data=request_value('createConsentArchiveExport',request.get_json(silent=True))
        with s.db(True) as db:
            require_runtime_ready(s,db);archives.owner_allowed(db,g.session['owner_id'])
            def action():return archives.queue(s,db,g.session['owner_id'],data),202,s.now()+86400
            return s.idempotent(db,g.session['owner_id'],action)

    @app.get('/v1/admin/consent-archive-exports')
    @auth('admin','records')
    def jobs():
        args=query(request.args,('cursor','limit'))
        with s.db() as db:
            rows,cursor=page(s,db,'consent_archive_exports','*','owner_id=?',[g.session['owner_id']],'exports',g.session['owner_id'],None,args.get('cursor'),limit_value(args))
            generation=require_runtime_ready(s,db);snapshots={};markers={}
            if rows:
                ids=[row['id'] for row in rows];placeholders=','.join('?' for _ in ids)
                snapshots={r['export_id']:r for r in db.execute('SELECT * FROM consent_archive_snapshots WHERE export_id IN ('+placeholders+')',ids).fetchall()}
                markers={r['export_id']:r['evidence_code'] for r in db.execute("SELECT export_id,evidence_code FROM consent_archive_events WHERE kind='queued' AND export_id IN ("+placeholders+')',ids).fetchall()}
            items=[archives.view(s,db,row,snapshots.get(row['id']),markers.get(row['id'])=='g:'+generation) for row in rows]
        return jsonify(items=items,next_cursor=cursor)

    @app.get('/v1/admin/consent-archive-exports/<export_id>')
    @auth('admin','records')
    def job(export_id):
        query(request.args,())
        with s.db() as db:return jsonify(archives.view(s,db,archives.load(db,g.session['owner_id'],export_id)))

    @app.get('/v1/admin/consent-archive-exports/<export_id>/events')
    @auth('admin','records')
    def events(export_id):
        args=query(request.args,('cursor','limit'))
        with s.db() as db:
            archives.load(db,g.session['owner_id'],export_id)
            rows,cursor=page(s,db,'consent_archive_events','*','export_id=?',[export_id],'export-events',g.session['owner_id'],export_id,args.get('cursor'),limit_value(args))
        return jsonify(items=[dict(event_id=r['id'],export_id=r['export_id'],kind=r['kind'],actor_type=r['actor_type'],actor_id=r['actor_id'],created_at_utc=utc(r['created_at']),
                                  correlation_id=r['correlation_id'],page_start=r['page_start'],page_end=r['page_end'],page_sha256=r['page_sha256'],evidence_code=r['evidence_code']) for r in rows],next_cursor=cursor)

    # Another records/settings administrator reviews any owner's request by its number.
    @app.get('/v1/admin/consent-archive-exports/<export_id>/approval')
    @auth('admin','records')
    def approval_review(export_id):
        query(request.args,())
        with s.db() as db:
            archives.owner_allowed(db,g.session['owner_id'])
            return jsonify(archives.approval_view(s,db,archives.load_any(db,export_id)))

    @app.post('/v1/admin/consent-archive-exports/<export_id>/approval')
    @auth('admin','records')
    def approve(export_id):
        data=request.get_json(silent=True)
        if not isinstance(data,dict) or set(data)!={'rows_sha256'} or not isinstance(data['rows_sha256'],str):fail('invalid_fields',400)
        with s.db(True) as db:
            require_runtime_ready(s,db)
            def action():
                row=archives.approve(s,db,g.session['owner_id'],export_id,data['rows_sha256'])
                return archives.approval_view(s,db,row),200,s.now()+86400
            return s.idempotent(db,g.session['owner_id'],action)

    @app.get('/v1/admin/consent-archive-exports/<export_id>/content')
    @auth('admin','records')
    def content(export_id):
        args=query(request.args,('cursor',));owner=g.session['owner_id']
        with s.db() as db:
            row=archives.load(db,owner,export_id);snapshot=db.execute('SELECT * FROM consent_archive_snapshots WHERE export_id=?',(export_id,)).fetchone()
            if not archives.ready_evidence(s,db,row,snapshot):fail('export_not_ready')
            if not archives.approval(db,row,snapshot):fail('export_approval_required')
            after,expires=decode_cursor(s,args.get('cursor'),'archive-content',owner,archives.snapshot_context(row,snapshot))
            if type(after) is not int or not 0<=after<=snapshot['item_count']:fail('cursor_invalid',400)
            if after==0:
                count,digest=archives.seal(db,snapshot['id'])
                if (count,digest)!=(snapshot['item_count'],snapshot['rows_sha256']):fail('snapshot_integrity_error',503)
            rows=db.execute('SELECT * FROM consent_archive_items WHERE snapshot_id=? AND ordinal>? ORDER BY ordinal LIMIT 1001',(snapshot['id'],after)).fetchall()
            selected=rows[:1000]
            for offset,item in enumerate(selected,after+1):
                if item['ordinal']!=offset or archives.item_hash(item,offset)!=item['row_sha256']:fail('snapshot_integrity_error',503)
            if len(selected)!=min(1000,snapshot['item_count']-after):fail('snapshot_integrity_error',503)
            next_cursor=encode_cursor(s,'archive-content',owner,selected[-1]['ordinal'],archives.snapshot_context(row,snapshot),expires) if len(rows)>1000 else ''
            output=io.StringIO(newline='');writer=csv.writer(output,lineterminator='\r\n');writer.writerow(archives.CSV_COLUMNS)
            def safe(value):
                text=str(value)
                return "'"+text if text.lstrip().startswith(('=','+','-','@','\t','\r')) else text
            for item in selected:
                value=public_row(item);writer.writerow([safe(value[column]) for column in archives.CSV_COLUMNS])
            result=('\ufeff'+output.getvalue()).encode('utf-8')
        with s.db(True) as db:
            require_runtime_ready(s,db);s.require_admin_transaction(db,g.session,'records');archives.owner_allowed(db,owner);fresh=archives.load(db,owner,export_id)
            if not archives.ready_evidence(s,db,fresh,snapshot):fail('export_not_ready')
            if not archives.approval(db,fresh,snapshot):fail('export_approval_required')
            start=after+1 if selected else after;end=selected[-1]['ordinal'] if selected else after
            archives.archive_event(s,db,export_id,'download_requested','admin',owner,page_start=start,page_end=end)
            archives.archive_event(s,db,export_id,'page_generated','admin',owner,page_start=start,page_end=end,page_sha=sha(result))
            s.audit(db,owner,'consent_archive_page_generated',export_id)
        response=make_response(result)
        response.headers['Content-Type']='text/csv; charset=utf-8'
        response.headers['Content-Disposition']='attachment; filename="consent-archive-'+identifier(export_id)+'-'+str(start)+'-'+str(end)+'.csv"'
        response.headers['X-Next-Cursor']=next_cursor
        response.headers['X-Snapshot-ID']=snapshot['id']
        return response
