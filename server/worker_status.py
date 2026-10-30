"""Shared last-job freshness for existing 120-second operational displays."""
from datetime import datetime,timezone
import re

FRESH_SECONDS=120
MAX_TIMESTAMP=253402300799

def _timestamp(value):
    if type(value) is int:return value if 0<=value<=MAX_TIMESTAMP else None
    if not isinstance(value,str) or not re.fullmatch(r'(?:0|[1-9][0-9]{0,11})',value):return None
    number=int(value)
    return number if number<=MAX_TIMESTAMP else None

def worker_status(raw,now):
    """Missing/invalid/future timestamps are stale; never clamp a future age to zero."""
    result=dict(last_success_utc=None,age_seconds=None,stale=True,state='missing' if raw is None else 'invalid')
    seen=_timestamp(raw);checked=_timestamp(now)
    if seen is None or checked is None:return result
    try:observed=datetime.fromtimestamp(seen,timezone.utc).isoformat().replace('+00:00','Z')
    except (ValueError,OverflowError,OSError):return result
    result['last_success_utc']=observed
    if seen>checked:
        result['state']='future'
        return result
    age=checked-seen
    result.update(age_seconds=age,stale=age>=FRESH_SECONDS,state='stale' if age>=FRESH_SECONDS else 'fresh')
    return result
