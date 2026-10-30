"""One canonical configuration for public display; reviewed plans apply while stopped."""
from pathlib import Path
import hashlib,json,os
from flask import g,jsonify
from filesystem_guard import is_link,regular
from jobs import secure_new_file
from security import protect_directory

TEXT_LIMITS={'name_ja':120,'name_en':120,'ssid':32,'contact_ja':200,'contact_en':200}
FIELDS=set(TEXT_LIMITS)|{'period_confirmed','service_start_utc','service_end_utc'}

def normalize(data):
    from app import timestamp,utc
    if not isinstance(data,dict) or set(data)!=FIELDS: raise ValueError('Invalid information fields')
    result=dict(data)
    for key,limit in TEXT_LIMITS.items():
        value=data[key]
        if value is None or value=='':result[key]=None;continue
        if not isinstance(value,str) or any(ord(c)<32 or ord(c)==127 for c in value):raise ValueError('Invalid display text')
        value=value.strip()
        if not value or (len(value.encode('utf-8')) if key=='ssid' else len(value))>limit:raise ValueError('Display text too long')
        result[key]=value
    if type(data['period_confirmed']) is not bool:raise ValueError('Invalid period confirmation')
    start,end=data['service_start_utc'],data['service_end_utc']
    if (start is None)!=(end is None):raise ValueError('Both period values are required')
    if start is not None:
        if utc(timestamp(start))!=start or utc(timestamp(end))!=end or timestamp(end)<=timestamp(start):raise ValueError('Invalid service period')
    if result['period_confirmed'] and start is None:raise ValueError('Confirmed period requires dates')
    return result

def current(config):
    values=config.get('event_information',{})
    if not isinstance(values,dict) or set(values)-set(TEXT_LIMITS)-{'period_confirmed'}:raise ValueError('Invalid event information')
    return normalize({**{key:values.get(key) for key in TEXT_LIMITS},'period_confirmed':values.get('period_confirmed',False),
                      'service_start_utc':config.get('service_start_utc'),'service_end_utc':config.get('service_end_utc')})

def public(config):
    data=current(config)
    if not data['period_confirmed']:data['service_start_utc']=data['service_end_utc']=None
    return data

def config_hash(home):return hashlib.sha256((home/'config.json').read_bytes()).hexdigest()

def make_plan(s,data,expected):
    if expected!=config_hash(s.home):raise ValueError('Configuration changed; reload the form')
    values=normalize(data)
    # Validate the resulting service configuration without connecting to APs or changing state.
    updated=json.loads((s.home/'config.json').read_text(encoding='utf-8'))
    updated['event_information']={key:values[key] for key in (*TEXT_LIMITS,'period_confirmed')}
    for key in ('service_start_utc','service_end_utc'):updated[key]=values[key]
    from app import Service
    candidate=Service.__new__(Service);candidate.home=s.home;candidate.config=updated;candidate.validate_config()
    return dict(format='festival-event-information-v1',created_at=s.now(),target_hash=hashlib.sha256(str(s.home).encode()).hexdigest(),
                config_sha256=expected,values=values,production_enabled=False,automatic_deletion_enabled=False)

def apply_plan(s,plan):
    from app import Service,uid
    from workflow_generation import stopped_config_change
    expected={'format','created_at','target_hash','config_sha256','values','production_enabled','automatic_deletion_enabled'}
    if not isinstance(plan,dict) or set(plan)!=expected or plan['format']!='festival-event-information-v1' or plan['production_enabled'] is not False or plan['automatic_deletion_enabled'] is not False:raise ValueError('Invalid information plan')
    if plan['target_hash']!=hashlib.sha256(str(s.home).encode()).hexdigest():raise ValueError('Plan target mismatch')
    with stopped_config_change(s):
        checked=make_plan(s,plan['values'],plan['config_sha256']);original=(s.home/'config.json').read_bytes();updated=json.loads(original)
        if hashlib.sha256(original).hexdigest()!=plan['config_sha256']:raise ValueError('Configuration changed')
        values=checked['values'];updated['event_information']={key:values[key] for key in (*TEXT_LIMITS,'period_confirmed')}
        if any(updated.get(key)!=values[key] for key in ('service_start_utc','service_end_utc')):updated['service_window_id']=uid()
        for key in ('service_start_utc','service_end_utc'):updated[key]=values[key]
        candidate=Service.__new__(Service);candidate.home=s.home;candidate.config=updated;candidate.validate_config()
        history=s.home/'configuration-history'
        if is_link(history):raise ValueError('Linked configuration history')
        history.mkdir(exist_ok=True);protect_directory(history);change=uid()
        secure_new_file(history/(change+'-event-before.json'),original)
        secure_new_file(history/(change+'-event-plan.json'),json.dumps(plan,ensure_ascii=False,indent=2).encode())
        body=json.dumps(updated,ensure_ascii=False,indent=2).encode();secure_new_file(history/(change+'-event-after.json'),body)
        with s.db(True) as db:s.audit(db,'local_cli','event_information_change_requested',change)
        replacement=s.home/('config-'+change+'.pending');secure_new_file(replacement,body);regular(s.home/'config.json');os.replace(replacement,s.home/'config.json')
        with s.db(True) as db:s.audit(db,'local_cli','event_information_changed',change)
    return dict(applied=True,restart_required=True,production_enabled=False,records_preserved=True)

def register(app,s,auth,body):
    from workflow_routes import register_event
    register_event(app,s,auth,body)
