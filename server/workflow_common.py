"""Shared bounded inputs, authenticated cursors and retained private source files."""
from contextlib import contextmanager
from pathlib import Path
import base64,hashlib,hmac,json,os,re,stat,uuid
from app import ROOT,ApiError,utc,timestamp
from filesystem_guard import is_link,regular
from security import protect_directory

API=json.loads((ROOT/'workflow-api.json').read_text(encoding='utf-8'))
ERRORS={e['code']:e for e in json.loads((ROOT/'workflow-errors.json').read_text(encoding='utf-8'))['errors']}
HEX=re.compile(r'^[0-9a-f]{64}$')

def canonical(value):return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')
def sha(value):return hashlib.sha256(value).hexdigest()
def fail(code,status=None):
    info=ERRORS.get(code,{})
    raise ApiError(code,status or info.get('status',409),info.get('message',code))
def identifier(value):
    if not isinstance(value,str):fail('invalid_fields',400)
    try:
        if str(uuid.UUID(value))!=value:raise ValueError()
    except ValueError:fail('invalid_fields',400)
    return value

def validate(schema,value):
    if '$ref' in schema:return validate(API['components']['schemas'][schema['$ref'].split('/')[-1]],value)
    if 'anyOf' in schema:
        for choice in schema['anyOf']:
            try:validate(choice,value);return value
            except ApiError:pass
        fail('invalid_fields',400)
    kind=schema.get('type')
    if kind=='null' and value is not None:fail('invalid_fields',400)
    if kind=='object':
        if not isinstance(value,dict) or set(schema.get('required',[]))-set(value):fail('invalid_fields',400)
        props=schema.get('properties',{})
        if schema.get('additionalProperties') is False and set(value)-set(props):fail('invalid_fields',400)
        for key,item in value.items():
            if key in props:validate(props[key],item)
    elif kind=='string':
        if not isinstance(value,str) or not schema.get('minLength',0)<=len(value)<=schema.get('maxLength',65536):fail('invalid_fields',400)
        if 'pattern' in schema and not re.search(schema['pattern'],value):fail('invalid_fields',400)
        if schema.get('format')=='uuid':identifier(value)
        if schema.get('format')=='date-time':
            try:
                if utc(timestamp(value))!=value:raise ValueError()
            except (ValueError,OverflowError,OSError):fail('invalid_fields',400)
    elif kind=='integer':
        if type(value) is not int or not schema.get('minimum',-2**63)<=value<=schema.get('maximum',2**63-1):fail('invalid_fields',400)
    elif kind=='boolean' and type(value) is not bool:fail('invalid_fields',400)
    elif kind=='array':
        if not isinstance(value,list):fail('invalid_fields',400)
        for item in value:validate(schema.get('items',{}),item)
    if 'enum' in schema and value not in schema['enum']:fail('invalid_fields',400)
    if 'const' in schema and value!=schema['const']:fail('invalid_fields',400)
    return value

def request_value(operation,value):
    for methods in API['paths'].values():
        for op in methods.values():
            if op['operationId']==operation:
                return validate(op['requestBody']['content']['application/json']['schema'],value)
    raise ValueError('Unknown operation')

def validate_policy(p,approved=True):
    bounds={'review_valid_seconds':(1,86400),'cursor_valid_seconds':(1,900),
            'export_row_limit':(1,100000),'export_range_seconds':(1,2678400),'owner_active_jobs':(1,1),
            'heartbeat_seconds':(1,60),'stale_after_seconds':(2,3600),'activation_grace_seconds':(2,86400)}
    if not isinstance(p,dict) or set(p)!=set(bounds)|{'approved'} or type(p.get('approved')) is not bool or p['approved'] is not approved:
        raise ApiError('workflow_policy_unconfigured',503,'確認期限・出力条件は未承認です。設定担当へ確認してください。')
    if any(type(p[k]) is not int or not low<=p[k]<=high for k,(low,high) in bounds.items()):fail('invalid_fields',400)
    if p['stale_after_seconds']<=p['heartbeat_seconds'] or p['activation_grace_seconds']<p['stale_after_seconds']:fail('invalid_fields',400)
    return p

def policy(s):return validate_policy(s.config.get('workflow_policy'))

def target(home):return sha(str(Path(home).resolve()).encode())
def private_dir(home,name):
    directory=Path(home)/name
    if is_link(directory):fail('storage_unavailable',503)
    directory.mkdir(exist_ok=True);protect_directory(directory)
    return directory

def read_private(home,directory,basename,limit=65536):
    if Path(basename).name!=basename or '/' in basename or '\\' in basename:fail('invalid_fields',400)
    home=Path(home).resolve();relative=Path(directory)
    if relative.is_absolute() or '..' in relative.parts:fail('storage_unavailable',503)
    root=home
    for part in relative.parts:
        root=root/part
        if is_link(root):fail('storage_unavailable',503)
    if not root.resolve().is_relative_to(home):fail('storage_unavailable',503)
    path=root/basename
    regular(path)
    with path.open('rb') as handle:
        before=os.fstat(handle.fileno());value=handle.read(limit+1);after=os.fstat(handle.fileno())
        identity=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)
        regular(path)
        if len(value)>limit or identity(before)!=identity(after) or identity(after)!=identity(path.lstat()):
            fail('storage_unavailable',503)
    return value

def strict_json(value):
    def pairs(items):
        result={}
        for key,item in items:
            if key in result:raise ValueError('Duplicate JSON key')
            result[key]=item
        return result
    def constant(_):raise ValueError('Nonfinite JSON')
    return json.loads(value.decode('utf-8'),object_pairs_hook=pairs,parse_constant=constant)

@contextmanager
def target_lock(home):
    directory=private_dir(home,'runtime');path=directory/'workflow-target.lock'
    if is_link(path):fail('storage_unavailable',503)
    if path.exists():regular(path)
    with path.open('a+b') as handle:
        if os.fstat(handle.fileno()).st_size==0:handle.write(b'1');handle.flush()
        handle.seek(0);locked=False
        try:
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
            locked=True;yield
        except OSError:
            if not locked:fail('lock_unavailable',503)
            raise
        finally:
            if locked and os.name=='nt':handle.seek(0);msvcrt.locking(handle.fileno(),msvcrt.LK_UNLCK,1)

def encode_cursor(s,scope,owner,position,context,expires=None):
    body=canonical(dict(scope=scope,owner=owner,position=position,context=context,
                        expires=expires or s.now()+policy(s)['cursor_valid_seconds']))
    token=base64.urlsafe_b64encode(body).rstrip(b'=')
    return (token+b'.'+hmac.new(s.key,b'workflow-cursor:'+token,hashlib.sha256).hexdigest().encode()).decode()

def decode_cursor(s,token,scope,owner,context):
    try:
        if not isinstance(token,str) or len(token)>2048:raise ValueError()
        raw,signature=token.encode('ascii').split(b'.')
        expected=hmac.new(s.key,b'workflow-cursor:'+raw,hashlib.sha256).hexdigest().encode()
        if not hmac.compare_digest(signature,expected):raise ValueError()
        value=strict_json(base64.urlsafe_b64decode(raw+b'='*((-len(raw))%4)))
        if set(value)!={'scope','owner','position','context','expires'} or (value['scope'],value['owner'],value['context'])!=(scope,owner,context):raise ValueError()
        if type(value['expires']) is not int or value['expires']<=s.now():fail('cursor_expired',409)
        return value['position'],value['expires']
    except (ValueError,TypeError,KeyError,UnicodeError):fail('cursor_invalid',400)

def query(args,allowed):
    if set(args)-set(allowed) or any(len(args.getlist(key))!=1 for key in args):fail('query_invalid',400)
    return dict(args)

def page(s,db,table,columns,where,params,scope,owner,context,cursor=None,limit=50,order=('created_at','id')):
    # Identifiers come only from callers' fixed source constants, never from HTTP.
    expires=None
    if cursor:
        position,expires=decode_cursor(s,cursor,scope,owner,context)
        if not isinstance(position,list) or len(position)!=2:fail('cursor_invalid',400)
        where+=' AND ('+order[0]+'<? OR ('+order[0]+'=? AND '+order[1]+'<?))'
        params=[*params,position[0],position[0],position[1]]
    rows=db.execute('SELECT '+columns+' FROM '+table+' WHERE '+where+' ORDER BY '+order[0]+' DESC,'+order[1]+' DESC LIMIT ?',[*params,limit+1]).fetchall()
    next_cursor=encode_cursor(s,scope,owner,[rows[limit-1][order[0]],rows[limit-1][order[1]]],context,expires) if len(rows)>limit else None
    return rows[:limit],next_cursor
