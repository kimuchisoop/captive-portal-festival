"""Durable notification handovers, immutable terms revisions, and storage history."""
import json
from flask import g,jsonify,request

def active_terms(s,lang,db):
    from app import digest
    r=db.execute('SELECT r.* FROM terms_publications p JOIN terms_revisions r ON r.id=p.revision_id ORDER BY p.seq DESC LIMIT 1').fetchone()
    if not r: return None
    text=r[lang]
    return dict(document_id=r['id'],version=r['version'],policy_version=r['policy_version'],language=lang,text=text,sha256=digest(text))

def sample_storage(s,storage):
    # An incomplete scan is a lower bound, unsuitable for a growth forecast.
    if not storage.get('backup_bytes_complete',True):return
    with s.db(True) as db:
        # One retained observation per UTC hour; polling does not create unlimited samples.
        db.execute('INSERT IGNORE INTO storage_samples VALUES (?,?,?,?,?)',
                   (s.now()//3600,s.now(),storage['database_allocated_bytes'],storage['backup_bytes'],storage['application_disk_free_bytes']))

def storage_history(s):
    from app import utc
    with s.db() as db:
        rows=db.execute('SELECT * FROM storage_samples ORDER BY bucket DESC LIMIT 744').fetchall()[::-1]
    result=dict(items=[dict(observed_at_utc=utc(r['observed_at']),database_bytes=r['database_bytes'],backup_bytes=r['backup_bytes'],
                           application_free_bytes=r['application_free_bytes']) for r in rows],
                sample_limit=744,minimum_span_hours=24,forecast=None,reason='insufficient_history',automatic_deletion_enabled=False)
    if len(rows)<3 or rows[-1]['observed_at']-rows[0]['observed_at']<86400: return result
    first,last=rows[0],rows[-1];days=(last['observed_at']-first['observed_at'])/86400
    estimates={}
    for key,column,threshold in [('database','database_bytes',s.config.get('db_warning_bytes')),
                                  ('backup','backup_bytes',s.config.get('backup_warning_bytes'))]:
        growth=(last[column]-first[column])/days
        estimates[key]=dict(bytes_per_day=round(growth),days_to_warning=round(max(0,(threshold-last[column])/growth),1)
                           if threshold is not None and growth>0 else None)
    result.update(forecast=estimates,reason='estimate_only')
    return result

def register_features(app,s,auth,body):
    from app import ApiError,uid,digest,utc

    @app.get('/v1/admin/notification-cases')
    @auth('admin','read')
    def cases():
        if set(request.args)-{'before'}: raise ApiError('query_invalid')
        before=request.args.get('before')
        if before:
            try: before=int(before)
            except ValueError: raise ApiError('query_invalid')
            if before<0: raise ApiError('query_invalid')
        with s.db() as db:
            notifications=db.execute('SELECT * FROM notifications ORDER BY first_seen DESC,id DESC LIMIT 100').fetchall()
            people=db.execute("SELECT id,username FROM admins WHERE enabled=1 AND role IN ('operator','settings') ORDER BY username").fetchall()
            history=db.execute('SELECT e.*,a.username AS actor_name,b.username AS assignee_name FROM notification_updates e '
                               'JOIN admins a ON a.id=e.actor LEFT JOIN admins b ON b.id=e.assignee '+
                               ('WHERE e.seq<? ' if before is not None else '')+'ORDER BY e.seq DESC LIMIT 101',
                               (before,) if before is not None else ()).fetchall()
            items=[]
            latest_by_notification={}
            if notifications:
                identifiers=[n['id'] for n in notifications]
                placeholders=','.join('?' for _ in identifiers)
                latest_rows=db.execute(
                    'SELECT e.id,e.notification_id,e.assignee,e.status,e.note,e.created_at,a.username AS assignee_name '
                    'FROM notification_updates e LEFT JOIN admins a ON a.id=e.assignee '
                    'JOIN (SELECT MAX(h.seq) AS seq FROM notification_updates h '
                    'JOIN notifications n ON n.id=h.notification_id AND n.generation=h.generation '
                    'WHERE h.notification_id IN ('+placeholders+') GROUP BY h.notification_id) latest ON latest.seq=e.seq',
                    identifiers).fetchall()
                for entry in latest_rows:
                    latest=dict(entry);notification_id=latest.pop('notification_id')
                    latest_by_notification[notification_id]=latest
            for n in notifications:
                latest=latest_by_notification.get(n['id'])
                items.append(dict(id=n['id'],code=n['code'],message=n['message'],condition=n['state'],generation=n['generation'],
                                  severity=n['severity'],workflow=dict(latest) if latest else None))
        return jsonify(items=items,assignees=[dict(p) for p in people],
                       history=[dict(e) for e in history[:100]],next_cursor=history[99]['seq'] if len(history)>100 else None)

    @app.post('/v1/admin/notification-cases/<notification_id>')
    @auth('admin','operate')
    def update_case(notification_id):
        d=body(('generation','expected_update_id','assignee','status','note'))
        if (type(d['generation']) is not int or d['status'] not in ('open','in_progress','handled')
            or not isinstance(d['note'],str) or not 1<=len(d['note'].strip())<=1000
            or any(v is not None and not isinstance(v,str) for v in (d['assignee'],d['expected_update_id']))):
            raise ApiError('handover_invalid',400,'対応状況と1〜1,000文字の引き継ぎ内容を確認してください。')
        with s.db(True) as db:
            def action():
                n=db.execute('SELECT * FROM notifications WHERE id=?',(notification_id,)).fetchone()
                if not n: raise ApiError('notification_not_found',404)
                latest=db.execute('SELECT id FROM notification_updates WHERE notification_id=? AND generation=? ORDER BY seq DESC LIMIT 1',
                                  (notification_id,n['generation'])).fetchone()
                if n['generation']!=d['generation'] or (latest['id'] if latest else None)!=d['expected_update_id']:
                    raise ApiError('handover_changed',409,'別の更新があります。一覧を更新して確認してください。')
                if d['assignee'] is not None and not db.execute("SELECT id FROM admins WHERE id=? AND enabled=1 AND role IN ('operator','settings')",(d['assignee'],)).fetchone():
                    raise ApiError('assignee_invalid')
                update_id=uid()
                db.execute('INSERT INTO notification_updates (id,notification_id,generation,actor,assignee,status,note,created_at) VALUES (?,?,?,?,?,?,?,?)',
                           (update_id,notification_id,n['generation'],g.session['owner_id'],d['assignee'],d['status'],d['note'].strip(),s.now()))
                s.audit(db,g.session['owner_id'],'notification_handover',notification_id)
                return dict(update_id=update_id,condition_unchanged=True),201,s.now()+86400
            return s.idempotent(db,g.session['owner_id'],action)

    def revision_public(r,full=False):
        return dict(id=r['id'],version=r['version'],policy_version=r['policy_version'],created_at_utc=utc(r['created_at']),
                    preview_sha256=digest(r['ja']+'\0'+r['en']),**({'ja':r['ja'],'en':r['en']} if full else {}))

    @app.get('/v1/admin/terms-revisions')
    @auth('admin','settings')
    def revisions():
        with s.db() as db:
            rows=db.execute('SELECT * FROM terms_revisions ORDER BY seq DESC LIMIT 100').fetchall()
            publication=db.execute('SELECT id,revision_id FROM terms_publications ORDER BY seq DESC LIMIT 1').fetchone()
        return jsonify(items=[revision_public(r) for r in rows],publication=dict(publication) if publication else None,scope='local_only')

    @app.get('/v1/admin/terms-revisions/<revision_id>')
    @auth('admin','settings')
    def revision(revision_id):
        with s.db() as db: row=db.execute('SELECT * FROM terms_revisions WHERE id=?',(revision_id,)).fetchone()
        if not row: raise ApiError('revision_not_found',404)
        return jsonify(revision_public(row,True))

    @app.post('/v1/admin/terms-revisions')
    @auth('admin','settings')
    def save_revision():
        d=body(('version','policy_version','ja','en'))
        for key,limit in [('version',80),('policy_version',80),('ja',5000),('en',5000)]:
            if not isinstance(d[key],str) or not 1<=len(d[key].strip())<=limit: raise ApiError('revision_invalid')
        with s.db(True) as db:
            def action():
                revision_id=uid()
                db.execute('INSERT INTO terms_revisions (id,version,policy_version,ja,en,actor,created_at) VALUES (?,?,?,?,?,?,?)',
                           (revision_id,d['version'].strip(),d['policy_version'].strip(),d['ja'],d['en'],g.session['owner_id'],s.now()))
                s.audit(db,g.session['owner_id'],'terms_draft_saved',revision_id)
                return dict(revision_id=revision_id,scope='local_only'),201,s.now()+86400
            return s.idempotent(db,g.session['owner_id'],action)

    @app.post('/v1/admin/terms-publications')
    @auth('admin','settings')
    def publish_revision():
        d=body(('revision_id','preview_sha256','expected_publication_id'))
        if not all(isinstance(d[k],str) for k in ('revision_id','preview_sha256')) or (d['expected_publication_id'] is not None and not isinstance(d['expected_publication_id'],str)):
            raise ApiError('publication_invalid')
        with s.db(True) as db:
            def action():
                r=db.execute('SELECT * FROM terms_revisions WHERE id=?',(d['revision_id'],)).fetchone()
                if not r: raise ApiError('revision_not_found',404)
                latest=db.execute('SELECT id FROM terms_publications ORDER BY seq DESC LIMIT 1').fetchone()
                if (latest['id'] if latest else None)!=d['expected_publication_id'] or digest(r['ja']+'\0'+r['en'])!=d['preview_sha256']:
                    raise ApiError('publication_changed',409,'規約の内容または適用状態が変わりました。再度プレビューしてください。')
                for lang in ('ja','en'):
                    existing=db.execute('SELECT * FROM terms_documents WHERE document_id=? AND language=?',(r['id'],lang)).fetchone()
                    if not existing: db.execute('INSERT INTO terms_documents VALUES (?,?,?,?,?)',(r['id'],lang,r['version'],digest(r[lang]),r[lang]))
                publication_id=uid()
                db.execute('INSERT INTO terms_publications (id,revision_id,actor,created_at) VALUES (?,?,?,?)',(publication_id,r['id'],g.session['owner_id'],s.now()))
                s.audit(db,g.session['owner_id'],'terms_published_local',r['id'])
                return dict(publication_id=publication_id,scope='local_only',production_enabled=False),201,s.now()+86400
            result=s.idempotent(db,g.session['owner_id'],action)
        s.forget_public_terms()  # after commit, so visitors see the new terms at once
        return result

    @app.get('/v1/admin/storage-history')
    @auth('admin','read')
    def history(): return jsonify(storage_history(s))
