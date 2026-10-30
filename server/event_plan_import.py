"""Local evidence preparation, then authenticated settings-owner registration."""
import re
from flask import g,request
from app import uid
from event_information import normalize,current
from workflow_common import canonical,sha,strict_json,read_private,private_dir,target,identifier,HEX,fail,target_lock,request_value
from workflow_generation import require_runtime_ready
from jobs import secure_new_file
import event_info_repository as plans

NAME=re.compile(r'^event-info-plan-([0-9a-f-]{36})\.json$')

def source(s,basename):
    match=NAME.fullmatch(basename)
    if not match:fail('invalid_fields',400)
    identifier(match[1]);raw=read_private(s.home,'configuration-history',basename);value=strict_json(raw)
    if not isinstance(value,dict) or set(value)!={'format','created_at','target_hash','config_sha256','values','production_enabled','automatic_deletion_enabled'}:raise ValueError('Invalid legacy plan')
    if value['format']!='festival-event-information-v1' or value['production_enabled'] is not False or value['automatic_deletion_enabled'] is not False:raise ValueError('Invalid legacy flags')
    if type(value['created_at']) is not int or value['created_at']<0 or any(not isinstance(value[k],str) or not HEX.fullmatch(value[k]) for k in ('target_hash','config_sha256')):raise ValueError('Invalid legacy fields')
    if normalize(value['values'])!=value['values']:raise ValueError('Noncanonical legacy values')
    return match[1],raw,value

def prepare(s,basename):
    with target_lock(s.home):
        with s.db() as db:generation=require_runtime_ready(s,db)
        report_id=uid();report=dict(format='festival-event-plan-import-review-v1',report_id=report_id,prepared_at=s.now(),prepared_by='local_cli',eligible=False,
            reason_codes=[],generation=generation,source_basename=basename,source_plan_id=None,source_sha256=None,source_created_at=None,target_hash=target(s.home),
            base_config_sha256=None,base_values=None,values=None,content_sha256=None,legacy_actor_id=None,production_enabled=False,automatic_deletion_enabled=False)
        try:
            plan_id,raw,value=source(s,basename);config_raw=read_private(s.home,'.','config.json');config=strict_json(config_raw)
            report.update(source_plan_id=plan_id,source_sha256=sha(raw),source_created_at=value['created_at'],base_config_sha256=value['config_sha256'],
                          base_values=current(config),values=value['values'],content_sha256=sha(canonical(value['values'])))
            if value['target_hash']!=target(s.home):report['reason_codes'].append('target_mismatch')
            if value['config_sha256']!=sha(config_raw):report['reason_codes'].append('config_changed')
            if read_private(s.home,'configuration-history',basename)!=raw or read_private(s.home,'.','config.json')!=config_raw:report['reason_codes'].append('source_changed')
            with s.db() as db:
                row=db.execute("SELECT actor FROM audit WHERE action='event_information_plan_saved' AND object_id=? ORDER BY created_at DESC,id DESC LIMIT 1",(plan_id,)).fetchone()
                if row:report['legacy_actor_id']=row['actor']
            report['eligible']=not report['reason_codes']
        except (OSError,ValueError,KeyError,TypeError,__import__('app').ApiError):report['reason_codes'].append('source_unavailable_or_invalid')
        directory=private_dir(s.home,'configuration-imports');raw=canonical(report)
        secure_new_file(directory/('import-report-'+report_id+'.json'),raw)
        return dict(report_id=report_id,report_sha256=sha(raw),eligible=report['eligible'],reason_codes=report['reason_codes'])

def commit(s,db,actor,data):
    generation=require_runtime_ready(s,db);identifier(data['report_id'])
    try:raw=read_private(s.home,'configuration-imports','import-report-'+data['report_id']+'.json')
    except FileNotFoundError:fail('import_report_not_found',404)
    if sha(raw)!=data['report_sha256']:fail('import_report_changed')
    try:report=strict_json(raw)
    except (ValueError,TypeError):fail('import_report_changed')
    expected={'format','report_id','prepared_at','prepared_by','eligible','reason_codes','generation','source_basename','source_plan_id','source_sha256','source_created_at','target_hash','base_config_sha256','base_values','values','content_sha256','legacy_actor_id','production_enabled','automatic_deletion_enabled'}
    if not isinstance(report,dict) or set(report)!=expected or report['format']!='festival-event-plan-import-review-v1' or report['report_id']!=data['report_id'] or report['prepared_by']!='local_cli' or report['eligible'] is not True or report['generation']!=generation or report['production_enabled'] is not False or report['automatic_deletion_enabled'] is not False:fail('invalid_state')
    try:plan_id,source_raw,value=source(s,report['source_basename'])
    except (OSError,ValueError,TypeError,KeyError):fail('import_source_changed')
    if report['target_hash']!=target(s.home) or value['target_hash']!=target(s.home):fail('invalid_state')
    if plan_id!=report['source_plan_id'] or sha(source_raw)!=report['source_sha256'] or value['values']!=report['values'] or sha(canonical(value['values']))!=report['content_sha256']:fail('import_source_changed')
    config_raw=read_private(s.home,'.','config.json')
    if sha(config_raw)!=data['expected_config_sha256'] or value['config_sha256']!=sha(config_raw) or report['base_config_sha256']!=sha(config_raw) or current(strict_json(config_raw))!=report['base_values']:fail('config_changed')
    if db.execute("SELECT plan_id FROM event_info_plan_events WHERE reason_code='legacy_import' AND kind='created' AND note LIKE ? LIMIT 1",('legacy-import|'+report['source_sha256']+'|%',)).fetchone():fail('import_already_registered')
    marker='|'.join(('legacy-import',report['source_sha256'],plan_id,report['report_id'],data['report_sha256']))
    result=plans.saved(s,db,actor,report['values'],report['base_config_sha256'],marker)
    if read_private(s.home,'configuration-history',report['source_basename'])!=source_raw or read_private(s.home,'configuration-imports','import-report-'+report['report_id']+'.json')!=raw:fail('import_source_changed')
    return result

def register_import(app,s,auth):
    @app.post('/v1/admin/event-information/plan-imports')
    @auth('admin','settings')
    def import_plan():
        data=request_value('commitLegacyEventPlanImport',request.get_json(silent=True))
        with target_lock(s.home),s.db(True) as db:
            require_runtime_ready(s,db);plans.settings_actor(db,g.session['owner_id'])
            def action():return commit(s,db,g.session['owner_id'],data),201,s.now()+86400
            return s.idempotent(db,g.session['owner_id'],action)
