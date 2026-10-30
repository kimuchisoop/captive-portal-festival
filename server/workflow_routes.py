"""Authenticated management routes for immutable information plans."""
from flask import g,jsonify,request
from app import uid,utc
from workflow_common import request_value,query,identifier,policy,encode_cursor,decode_cursor,page,fail,target_lock,read_private,sha
from workflow_generation import require_runtime_ready,runtime_observations
import event_info_repository as plans

def limit_value(args):
    try:
        raw=args.get('limit','50');value=int(raw)
        if not 1<=value<=100 or str(value)!=raw:raise ValueError()
        return value
    except (ValueError,TypeError):fail('query_invalid',400)

def observed(row):
    return dict(observation_id=row['id'],version=row['observation_version'],outcome=row['outcome'],
                observed_config_sha256=row['observed_config_sha256'],evidence_code=row['evidence_code'],created_at_utc=utc(row['created_at']))

def attempt(db,row):
    latest=db.execute('SELECT * FROM event_info_apply_observations WHERE attempt_id=? ORDER BY observation_version DESC LIMIT 1',(row['id'],)).fetchone()
    return dict(attempt_id=row['id'],created_at_utc=utc(row['created_at']),review_event_id=row['review_event_id'],
                before_config_sha256=row['before_config_sha256'],expected_after_config_sha256=row['expected_after_config_sha256'],latest_observation=observed(latest) if latest else None)

def application_status(s,db,plan_id):
    plans.load(db,plan_id)
    row=db.execute('SELECT * FROM event_info_apply_attempts WHERE plan_id=? ORDER BY created_at DESC,id DESC LIMIT 1',(plan_id,)).fetchone()
    latest=attempt(db,row) if row else None
    try:current=sha(read_private(s.home,'.','config.json'))
    except (OSError,ValueError,__import__('app').ApiError):current=None
    runtime=runtime_observations(s,db);app=runtime['app'];worker=runtime['worker']
    relation='not_attempted' if not row else 'unavailable' if current is None else 'expected_after' if current==row['expected_after_config_sha256'] else 'before' if current==row['before_config_sha256'] else 'other'
    superseding=None
    if row and relation=='other':
        known=db.execute('SELECT plan_id FROM event_info_apply_attempts WHERE expected_after_config_sha256=? AND id<>? ORDER BY created_at DESC,id DESC LIMIT 1',(current,row['id'])).fetchone()
        if known:relation='subsequent_known';superseding=known['plan_id']
    activation='not_attempted' if not row else 'superseded' if superseding else 'conflict' if relation=='other' else 'unknown'
    if row and relation=='expected_after':
        app_match=app['state']=='active' and app['config_sha256']==current
        worker_match=worker['state']=='active' and worker['config_sha256']==current
        activation='matched' if app_match and worker_match else 'partial' if app_match or worker_match else 'restart_required'
    return dict(plan_id=plan_id,latest_attempt=latest,config_file_sha256=current,file_relation=relation,superseding_plan_id=superseding,
                app_instance_id=app.get('instance') or s.instance_id,app_loaded_config_sha256=s.loaded_config_sha256,
                worker_instance_id=worker.get('instance'),worker_loaded_config_sha256=worker['config_sha256'],worker_last_seen_at_utc=worker['seen_at_utc'],
                worker_freshness='fresh' if worker['state']=='active' else 'unknown',activation_state=activation,network_verified=False,scope='local_display_only')

def register_event(app,s,auth,body):
    from event_information import current,config_hash
    @app.get('/v1/admin/event-information')
    @auth('admin','settings')
    def get_info():return jsonify(values=current(s.config),config_sha256=config_hash(s.home),scope='local_display_only')

    @app.post('/v1/admin/event-information/plans')
    @auth('admin','settings')
    def save_info_plan():
        data=body(('values','config_sha256'))
        with target_lock(s.home),s.db(True) as db:
            require_runtime_ready(s,db);plans.settings_actor(db,g.session['owner_id'])
            def action():
                try:
                    request_value('saveEventInformationPlan',data)
                    result=plans.saved(s,db,g.session['owner_id'],data['values'],data['config_sha256'])
                except __import__('app').ApiError as error:
                    if error.code=='invalid_fields':fail('event_information_invalid')
                    raise
                except (ValueError,TypeError,KeyError):fail('event_information_invalid')
                return result,201,s.now()+86400
            return s.idempotent(db,g.session['owner_id'],action)

    @app.get('/v1/admin/event-information/plans')
    @auth('admin','settings')
    def list_plans():
        args=query(request.args,('cursor','limit','state','created_by'));limit=limit_value(args)
        filters={key:args[key] for key in ('state','created_by') if key in args};where='1=1';params=[]
        if 'state' in filters:
            if filters['state'] not in ('saved','review_pending','reviewed','withdrawn'):fail('query_invalid',400)
            where+=' AND e.state_after=?';params.append(filters['state'])
        if 'created_by' in filters:where+=' AND p.created_by=?';params.append(filters['created_by'])
        expires=None;owner=g.session['owner_id']
        if args.get('cursor'):
            position,expires=decode_cursor(s,args['cursor'],'plans',owner,filters)
            if not isinstance(position,list) or len(position)!=2:fail('cursor_invalid',400)
            where+=' AND (p.created_at<? OR (p.created_at=? AND p.id<?))';params.extend((position[0],position[0],position[1]))
        with s.db() as db:
            generation=require_runtime_ready(s,db);config=read_private(s.home,'.','config.json')
            rows=db.execute(plans.PLAN_SELECT+'WHERE '+where+' ORDER BY p.created_at DESC,p.id DESC LIMIT ?',params+[limit+1]).fetchall()
            items=[plans.view(s,db,row,False,config,generation) for row in rows[:limit]]
            cursor=encode_cursor(s,'plans',owner,[rows[limit-1]['created_at'],rows[limit-1]['id']],filters,expires) if len(rows)>limit else None
        return jsonify(items=items,next_cursor=cursor)

    @app.get('/v1/admin/event-information/plans/<plan_id>')
    @auth('admin','settings')
    def get_plan(plan_id):
        query(request.args,())
        with s.db() as db:return jsonify(plans.view(s,db,plans.load(db,plan_id)))

    @app.get('/v1/admin/event-information/plans/<plan_id>/events')
    @auth('admin','settings')
    def plan_events(plan_id):
        args=query(request.args,('cursor','limit'))
        with s.db() as db:
            plans.load(db,plan_id)
            rows,cursor=page(s,db,'event_info_plan_events','*','plan_id=?',[plan_id],'plan-events',g.session['owner_id'],plan_id,args.get('cursor'),limit_value(args),('plan_version','id'))
        return jsonify(items=[dict(event_id=r['id'],plan_id=r['plan_id'],version=r['plan_version'],kind=r['kind'],state_after=r['state_after'],actor_id=r['actor_id'],
                                  created_at_utc=utc(r['created_at']),confirmed_content_sha256=r['confirmed_content_sha256'],review_valid_until_utc=utc(r['review_valid_until']) if r['review_valid_until'] is not None else None,
                                  reason_code=r['reason_code'],note=r['note']) for r in rows],next_cursor=cursor)

    def register_transition(suffix,operation,kind):
        @auth('admin','settings')
        def change(plan_id):
            identifier(plan_id);data=request_value(operation,request.get_json(silent=True))
            with target_lock(s.home),s.db(True) as db:
                require_runtime_ready(s,db);plans.settings_actor(db,g.session['owner_id'])
                def action():return plans.transition(s,db,g.session['owner_id'],plan_id,data,kind),200,s.now()+86400
                return s.idempotent(db,g.session['owner_id'],action)
        app.add_url_rule('/v1/admin/event-information/plans/<plan_id>/'+suffix,'workflow_'+suffix,change,methods=['POST'])
    register_transition('review-requests','requestEventInformationReview','review_requested')
    register_transition('reviews','recordEventInformationReview','review_recorded')
    register_transition('withdrawals','withdrawEventInformationPlan','withdrawn')

    @app.get('/v1/admin/event-information/plans/<plan_id>/application-status')
    @auth('admin','settings')
    def status(plan_id):
        query(request.args,())
        with s.db() as db:return jsonify(application_status(s,db,identifier(plan_id)))

    @app.get('/v1/admin/event-information/plans/<plan_id>/apply-attempts')
    @auth('admin','settings')
    def attempts(plan_id):
        args=query(request.args,('cursor','limit'))
        with s.db() as db:
            plans.load(db,plan_id)
            rows,cursor=page(s,db,'event_info_apply_attempts','*','plan_id=?',[plan_id],'plan-attempts',g.session['owner_id'],plan_id,args.get('cursor'),limit_value(args))
            items=[attempt(db,r) for r in rows]
        return jsonify(items=items,next_cursor=cursor)

    @app.get('/v1/admin/event-information/plans/<plan_id>/apply-attempts/<attempt_id>/observations')
    @auth('admin','settings')
    def observations(plan_id,attempt_id):
        args=query(request.args,('cursor','limit'));identifier(plan_id);identifier(attempt_id)
        with s.db() as db:
            if not db.execute('SELECT 1 FROM event_info_apply_attempts WHERE id=? AND plan_id=?',(attempt_id,plan_id)).fetchone():fail('attempt_not_found',404)
            rows,cursor=page(s,db,'event_info_apply_observations','*','attempt_id=?',[attempt_id],'plan-observations',g.session['owner_id'],[plan_id,attempt_id],args.get('cursor'),limit_value(args),('observation_version','id'))
        return jsonify(items=[observed(r) for r in rows],next_cursor=cursor)

    from event_plan_import import register_import
    register_import(app,s,auth)
