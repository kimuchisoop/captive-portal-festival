"""Generate minimum browser contracts into a NEW directory; stdlib only.

No application imports, JavaScript execution, network, database or test runner.
This shipped maintenance tool has not been run for the candidate release.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import sys

SCHEMA_KEYS={'type','required','properties','items','anyOf','allOf','if','then',
             'enum','const','pattern','format','minLength','maxLength','additionalProperties'}
TYPES={'null','string','boolean','integer','number','array','object'}

def scalar(value):
    return value is None or type(value) in (str,bool,int,float)

def check_schema(schema,depth=0):
    if depth>32 or not isinstance(schema,dict) or not set(schema)<=SCHEMA_KEYS:
        raise ValueError('Unsupported schema structure')
    if 'type' in schema and schema['type'] not in TYPES:
        raise ValueError('Unsupported type')
    if 'additionalProperties' in schema and schema['additionalProperties'] is not True:
        raise ValueError('Only additionalProperties:true is supported')
    for key in ('items','if','then'):
        if key in schema:check_schema(schema[key],depth+1)
    for key in ('anyOf','allOf'):
        if key in schema:
            if not isinstance(schema[key],list) or not schema[key]:
                raise ValueError('Schema alternatives must be nonempty arrays')
            for child in schema[key]:check_schema(child,depth+1)
    if schema.get('type')=='array' and 'items' not in schema:
        raise ValueError('Array item schema is required')
    if 'properties' in schema:
        if not isinstance(schema['properties'],dict):raise ValueError('Properties must be an object')
        for child in schema['properties'].values():check_schema(child,depth+1)
    if 'required' in schema:
        value=schema['required']
        if not isinstance(value,list) or any(not isinstance(k,str) for k in value) or len(set(value))!=len(value):
            raise ValueError('Invalid required keys')
        if not set(value)<=set(schema.get('properties',{})):
            raise ValueError('Required keys need property definitions')
    for key in ('minLength','maxLength'):
        if key in schema and (type(schema[key]) is not int or schema[key]<0):
            raise ValueError('Invalid string length limit')
    if schema.get('format','date-time')!='date-time':raise ValueError('Unsupported format')
    if 'pattern' in schema and not isinstance(schema['pattern'],str):raise ValueError('Invalid pattern type')
    if 'const' in schema and not scalar(schema['const']):raise ValueError('Only scalar constants are supported')
    if 'enum' in schema and (not isinstance(schema['enum'],list) or not schema['enum'] or not all(scalar(v) for v in schema['enum'])):
        raise ValueError('Only nonempty scalar enums are supported')

def packed_definitions(definition):
    if definition.get('definition_format')!=1 or not isinstance(definition.get('operations'),dict):
        raise ValueError('Unsupported definition format')
    shapes=[]
    identifiers={}
    def intern(schema):
        key=json.dumps(schema,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)
        if key in identifiers:return identifiers[key]
        item=dict(schema)
        for field in ('items','if','then'):
            if field in item:item[field]=intern(item[field])
        for field in ('anyOf','allOf'):
            if field in item:item[field]=[intern(child) for child in item[field]]
        if 'properties' in item:item['properties']={key:intern(value) for key,value in sorted(item['properties'].items())}
        index=len(shapes)
        shapes.append(item)
        identifiers[key]=index
        return index
    rules=[]
    for operation,schema in sorted(definition['operations'].items()):
        if not re.fullmatch(r'(GET|POST|PUT|PATCH|DELETE) /v1/[A-Za-z0-9_<>/-]+',operation):
            raise ValueError('Unsupported operation name')
        if schema is None:continue
        check_schema(schema)
        method,path=operation.split(' ',1)
        rules.append(dict(method=method,path=path,schema=intern(schema)))
    return shapes,rules

def sha(value):return hashlib.sha256(value).hexdigest()

def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate JSON object key')
        result[key]=value
    return result

def main():
    parser=argparse.ArgumentParser(description='Write browser definitions and a document mirror to a new directory; never overwrite existing files.')
    parser.add_argument('--output-dir',required=True,help='New directory whose parent already exists')
    args=parser.parse_args()
    here=Path(__file__).resolve().parent
    source_bytes=(here/'response-contracts.source.json').read_bytes()
    template_bytes=(here/'response-contracts.runtime.js.in').read_bytes()
    definition=json.loads(source_bytes.decode('utf-8'),object_pairs_hook=unique_object)
    shapes,rules=packed_definitions(definition)
    template=template_bytes.decode('utf-8')
    markers=('__SFF_RESPONSE_SHAPES__','__SFF_RESPONSE_RULES__')
    if any(template.count(marker)!=1 for marker in markers):raise ValueError('Invalid template markers')
    pack=lambda value:json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)
    javascript=template.replace(markers[0],pack(shapes)).replace(markers[1],pack(rules)).encode('utf-8')
    files={'response-contracts.js':javascript,'画面用最小定義.json':source_bytes}
    record=dict(source_release=definition.get('source_release'),operation_count=len(definition['operations']),json_success_shapes=len(rules),
                source_sha256=sha(source_bytes),template_sha256=sha(template_bytes),tool_sha256=sha(Path(__file__).read_bytes()),
                files={name:sha(value) for name,value in files.items()},application_executed=False,tests_executed=False)
    files['生成記録.json']=(json.dumps(record,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode('utf-8')
    destination=Path(args.output_dir).resolve()
    destination.mkdir(exist_ok=False)
    for name,value in files.items():
        with (destination/name).open('xb') as handle:handle.write(value)
    print('Generated 3 files in a new directory. Review before adoption; runtime tests were not performed.')

if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,TypeError,RecursionError):
        print('Generation stopped. Inputs may be unsupported or the output directory may already exist. Existing files and any partial output were retained; use a different new directory after review.',file=sys.stderr)
        raise SystemExit(1)
