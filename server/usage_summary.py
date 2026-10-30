"""Hourly anonymous counts in existing meta; no request identifiers or raw payloads."""
from datetime import datetime,timedelta,timezone
from flask import jsonify,request
from database import transaction

JST=timezone(timedelta(hours=9))
PREFIX='usage:v1:'

def bucket(ts): return datetime.fromtimestamp(ts,timezone.utc).strftime('%Y%m%dT%H')

def increment(s,kind):
    if kind not in ('client_error','server_error'): raise ValueError('Unknown aggregate')
    with transaction(s.db_settings,True) as db:
        # Existing application lock serializes the tiny increment with backup writes.
        db.execute('INSERT INTO meta (name,value) VALUES (?,?) ON DUPLICATE KEY UPDATE value=CAST(value AS UNSIGNED)+1',(PREFIX+bucket(s.now())+':'+kind,'1'))

def summary(s,day):
    if not isinstance(day,str) or len(day)!=10: raise ValueError('Invalid date')
    start=datetime.strptime(day,'%Y-%m-%d').replace(tzinfo=JST)
    if start.date().isoformat()!=day: raise ValueError('Invalid date')
    from app import utc
    lower=int(start.timestamp());upper=lower+86400
    keys=[PREFIX+bucket(lower+hour*3600)+':'+kind for hour in range(24) for kind in ('client_error','server_error')]
    with s.db() as db:
        consents=db.execute('SELECT SUBSTRING(accepted_at_utc,1,13) AS hour_key,COUNT(*) AS total FROM consents WHERE accepted_at_utc>=? AND accepted_at_utc<? GROUP BY hour_key',(utc(lower),utc(upper))).fetchall()
        totals={r['hour_key']:int(r['total']) for r in consents}
        counts={r['name']:int(r['value']) for r in db.execute('SELECT name,value FROM meta WHERE name IN ('+','.join('?' for _ in keys)+')',keys).fetchall()}
        began=db.execute('SELECT value FROM meta WHERE name=?',(PREFIX+'started_at',)).fetchone()
    hours=[]
    for hour in range(24):
        ts=lower+hour*3600;prefix=PREFIX+bucket(ts)+':'
        hours.append(dict(hour_jst=f'{hour:02d}:00',consents=totals.get(utc(ts)[:13],0),client_errors=counts.get(prefix+'client_error',0),server_errors=counts.get(prefix+'server_error',0)))
    return dict(day_jst=day,time_zone='Asia/Tokyo',hours=hours,total_consents=sum(h['consents'] for h in hours),total_errors=sum(h['client_errors']+h['server_errors'] for h in hours),
                error_collection_started_at_utc=began[0] if began else None,unrecorded_errors_current_process=getattr(s,'unrecorded_usage_errors',0),
                scope='stored consents and recorded visitor API error responses; not connected devices',automatic_deletion_enabled=False)

def register(app,s,auth):
    from app import utc
    s.unrecorded_usage_errors=0
    try:
        with s.db(True) as db: db.execute('INSERT IGNORE INTO meta (name,value) VALUES (?,?)',(PREFIX+'started_at',utc(s.now())))
    except Exception: app.logger.warning('usage_collection_start_unavailable')

    @app.after_request
    def count_errors(response):
        path=request.path
        if path.startswith('/v1/') and path!='/v1/admin' and not path.startswith('/v1/admin/') and 400<=response.status_code<=599:
            try: increment(s,'server_error' if response.status_code>=500 else 'client_error')
            except Exception:
                s.unrecorded_usage_errors+=1
                app.logger.warning('usage_error_count_unavailable')
        return response

    @app.get('/v1/admin/usage-summary')
    @auth('admin','read')
    def usage():
        from app import ApiError
        day=request.args.get('day',datetime.fromtimestamp(s.now(),JST).date().isoformat())
        if set(request.args)-{'day'} or len(request.args.getlist('day'))>1: raise ApiError('invalid_summary_date')
        try: payload=summary(s,day)
        except ValueError: raise ApiError('invalid_summary_date')
        return jsonify(payload)
