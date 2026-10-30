"""Daily opening hours inside the service window; explicit stopped-service application, history kept."""
import json,os,re
from app import uid
from jobs import secure_new_file
from workflow_common import read_private,private_dir

FIELDS={'open','close','utc_offset_minutes'}

def minutes(value):
    match=re.fullmatch(r'([01][0-9]|2[0-3]):([0-5][0-9])',value) if isinstance(value,str) else None
    if not match:raise ValueError('Daily hours use HH:MM')
    return int(match[1])*60+int(match[2])

def validate(hours):
    if hours is None:return None
    if not isinstance(hours,dict) or set(hours)!=FIELDS:raise ValueError('Invalid daily_service_hours')
    offset=hours['utc_offset_minutes']
    if type(offset) is not int or not -720<=offset<=840:raise ValueError('Invalid daily hours offset')
    # Same-day hours only; an overnight range is a different operating decision.
    if minutes(hours['open'])>=minutes(hours['close']):raise ValueError('Daily hours must open before they close')
    return hours

def is_open(hours,now):
    if hours is None:return True
    local=(int(now)//60+hours['utc_offset_minutes'])%1440
    return minutes(hours['open'])<=local<minutes(hours['close'])

def apply(s,hours):
    from workflow_generation import stopped_config_change
    validate(hours)
    with stopped_config_change(s):
        original=read_private(s.home,'.','config.json');updated=json.loads(original)
        updated['daily_service_hours']=hours
        from app import Service
        candidate=Service.__new__(Service);candidate.home=s.home;candidate.config=updated;candidate.validate_config()
        change=uid();directory=private_dir(s.home,'configuration-history')
        body=json.dumps(updated,ensure_ascii=False,indent=2).encode()
        secure_new_file(directory/(change+'-daily-hours-before.json'),original)
        secure_new_file(directory/(change+'-daily-hours-after.json'),body)
        with s.db(True) as db:s.audit(db,'local_cli','daily_service_hours_change_requested',change)
        replacement=s.home/('config-'+change+'.pending');secure_new_file(replacement,body)
        if read_private(s.home,'.','config.json')!=original:raise ValueError('Configuration changed')
        os.replace(replacement,s.home/'config.json')
        with s.db(True) as db:s.audit(db,'local_cli','daily_service_hours_changed',change)
    return dict(applied=True,daily_service_hours=hours,restart_required=True,production_enabled=False)
