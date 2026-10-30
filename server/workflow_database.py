"""Explicit schema-five maintenance and conservative table/column grant diagnosis."""
from pathlib import Path
import json,re,os
from app import ROOT,uid
from database import load_settings,transaction,Connection,connect
from filesystem_guard import regular
from preflight import private_paths
from workflow_common import canonical,sha,target_lock,private_dir,read_private
from workflow_generation import create_generation
from jobs import secure_new_file

CONTRACT=json.loads((ROOT/'workflow-contract.json').read_text(encoding='utf-8'))
TABLES={table['name']:table for table in CONTRACT['tables']}

def maintenance_settings(path,runtime):
    regular(path)
    if not private_paths([Path(path)]):raise ValueError('Protected maintenance settings required')
    maintenance=load_settings(path)
    if (maintenance['host'].lower(),maintenance['port'],maintenance['database'])!=(runtime['host'].lower(),runtime['port'],runtime['database']):raise ValueError('Maintenance database differs')
    if maintenance['user']==runtime['user']:raise ValueError('Separate maintenance account required')
    return maintenance

def verify_contract(db,partial=False):
    existing={r['TABLE_NAME']:r['ENGINE'] for r in db.execute("SELECT TABLE_NAME,ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE'").fetchall()}
    if set(existing)-set(TABLES) or (not partial and set(existing)!=set(TABLES)):raise ValueError('Unexpected table set')
    for name in existing:
        if existing[name]!='InnoDB':raise ValueError('InnoDB required')
        columns=db.execute('SHOW COLUMNS FROM `'+name+'`').fetchall()
        expected=TABLES[name]
        def normalize(value):
            value=re.sub(r'\s+',' ',value.strip().lower())
            return re.sub(r'\b(bigint|int|integer|smallint|mediumint|tinyint)\([0-9]+\)',r'\1',value)
        if [(r['Field'],normalize(r['Type']),r['Null']=='YES') for r in columns]!=[(r['name'],normalize(r['sql_type']),r['nullable']) for r in expected['columns']]:raise ValueError('Column contract differs')
        keys=db.execute('SHOW INDEX FROM `'+name+'`').fetchall()
        primary=[r['Column_name'] for r in sorted((r for r in keys if r['Key_name']=='PRIMARY'),key=lambda r:r['Seq_in_index'])]
        if primary!=expected['primary']:raise ValueError('Primary key differs')
    return True

def statements(path):
    text='\n'.join(line for line in Path(path).read_text(encoding='utf-8').splitlines() if not line.lstrip().startswith('--'))
    return [part.strip() for part in text.split(';') if part.strip()]

def migrate(home,maintenance_file):
    from recovery_kit import stopped
    home=Path(home).resolve();runtime=load_settings(home/'mysql.json');settings=maintenance_settings(maintenance_file,runtime)
    with stopped(home),target_lock(home):
        from filesystem_guard import is_link
        if any((home/name).exists() or is_link(home/name) for name in ('initialization.incomplete','restore.incomplete','policy-apply.incomplete')):
            raise ValueError('Complete the other retained operation before schema maintenance')
        marker=home/'upgrade.incomplete'
        if is_link(marker):raise ValueError('Linked upgrade guard')
        with transaction(settings,True) as db:
            version=db.execute("SELECT value FROM meta WHERE name='schema_version'").fetchone()
            if not version or version[0] not in ('4','5'):raise ValueError('Schema four required')
            if version[0]=='5' and not marker.exists():verify_contract(db);return dict(changed=False)
            verify_contract(db,partial=True)
            if not marker.exists():secure_new_file(marker,canonical(dict(format='schema5-upgrade',id=uid())))
            history=private_dir(home,'migration-history')
            for sql in statements(ROOT/'features-v5.sql'):
                skip=False
                match=re.match(r'CREATE TABLE (\w+)\b',sql,re.I)
                if match:skip=bool(db.execute('SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?',(match[1],)).fetchone())
                match=re.match(r'CREATE TRIGGER (\w+)\b',sql,re.I)
                if match:
                    old=db.execute('SELECT ACTION_STATEMENT,EVENT_MANIPULATION,EVENT_OBJECT_TABLE,ACTION_TIMING FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND TRIGGER_NAME=?',(match[1],)).fetchone()
                    if old:
                        expected=re.match(r'CREATE TRIGGER \w+ (BEFORE|AFTER) (UPDATE|DELETE|INSERT) ON (\w+) FOR EACH ROW (.+)',sql,re.I|re.S)
                        compact=lambda value:re.sub(r'\s+',' ',value.replace('`','').strip()).lower()
                        if not expected or (old['ACTION_TIMING'],old['EVENT_MANIPULATION'],old['EVENT_OBJECT_TABLE'])!=(expected[1].upper(),expected[2].upper(),expected[3]) or compact(old['ACTION_STATEMENT'])!=compact(expected[4]):raise ValueError('Existing trigger differs')
                        skip=True
                match=re.match(r'CREATE (?:UNIQUE )?INDEX (\w+) ON (\w+)\s*\((.+)\)',sql,re.I|re.S)
                if match:
                    old=db.execute('SHOW INDEX FROM `'+match[2]+'` WHERE Key_name=?',(match[1],)).fetchall()
                    if old:
                        actual=[r['Column_name']+(('('+str(r['Sub_part'])+')') if r['Sub_part'] else '') for r in sorted(old,key=lambda r:r['Seq_in_index'])]
                        expected=[item.strip().replace('`','') for item in match[3].split(',')]
                        if actual!=expected:raise ValueError('Existing index differs')
                        skip=True
                if not skip:db.execute(sql)
                secure_new_file(history/('statement-'+uid()+'.json'),canonical(dict(sql_sha256=sha(sql.encode()),status='existing' if skip else 'created')))
            verify_contract(db)
            config=__import__('workflow_common').strict_json(read_private(home,'.','config.json'))
            config['backup_format']='stream-v2'
            if not isinstance(config.get('workflow_policy'),dict):config['workflow_policy']=json.loads((ROOT/'workflow-policy.proposal.json').read_text(encoding='utf-8'))
            config['workflow_policy']['approved']=False
            before=read_private(home,'.','config.json');change=uid();directory=private_dir(home,'configuration-history')
            secure_new_file(directory/(change+'-upgrade-before.json'),before)
            updated=canonical(config);secure_new_file(directory/(change+'-upgrade-after.json'),updated)
            replacement=home/('config-'+change+'.pending');secure_new_file(replacement,updated)
            if read_private(home,'.','config.json')!=before:raise ValueError('Config changed')
            os.replace(replacement,home/'config.json')
            db.execute("UPDATE meta SET value='5' WHERE name='schema_version'")
            if not db.execute("SELECT 1 FROM meta WHERE name='runtime5_generation'").fetchone():create_generation(db,__import__('time').time_ns()//10**9)
        destination=history/('upgrade-'+uid()+'.completed.json')
        if not marker.resolve().is_relative_to(home) or not destination.resolve().is_relative_to(home):raise ValueError('Unsafe marker move')
        os.rename(marker,destination)
        return dict(changed=True,schema_version=5,records_preserved=True)

def split_privileges(text):
    parts=[];start=0;depth=0;quoted=False;index=0
    while index<len(text):
        char=text[index]
        if char=='`':
            if quoted and index+1<len(text) and text[index+1]=='`':index+=2;continue
            quoted=not quoted
        elif not quoted:
            if char=='(':depth+=1
            elif char==')':depth-=1
            elif char==',' and depth==0:parts.append(text[start:index].strip());start=index+1
            if depth<0:raise ValueError('Unknown privilege expression')
        index+=1
    if quoted or depth:raise ValueError('Unknown privilege expression')
    return parts+[text[start:].strip()]

def inspect_grants(grants,database,roles):
    contract=json.loads((ROOT/'workflow-privileges.json').read_text(encoding='utf-8'))
    expected={r['table']:r for r in contract['runtime']};actual={name:dict(select=False,insert=False,delete=False,update_columns=set()) for name in expected}
    reasons=[]
    for line in grants:
        match=re.fullmatch(r'GRANT (.+?) ON (.+?) TO .+',line,re.I)
        if not match:reasons.append('unknown_or_role_grant');continue
        if match[1].upper()=='USAGE' and match[2]=='*.*':continue
        if 'WITH GRANT OPTION' in line.upper():reasons.append('grant_option')
        scope=re.fullmatch(r'`([^`]+)`\.`([^`]+)`',match[2])
        if not scope or scope[1]!=database or scope[2] not in expected:reasons.append('outside_table_contract');continue
        try:parts=split_privileges(match[1])
        except ValueError:reasons.append('unknown_privilege_expression');continue
        for privilege in parts:
            if privilege.upper() in ('SELECT','INSERT','DELETE'):actual[scope[2]][privilege.lower()]=True;continue
            columns=re.fullmatch(r'UPDATE\s*\((.+)\)',privilege,re.I)
            if columns:
                values=[item.strip() for item in columns[1].split(',')]
                if all(re.fullmatch(r'(?:`[a-z_][a-z0-9_]*`|[a-z_][a-z0-9_]*)',item) for item in values):actual[scope[2]]['update_columns'].update(item.strip('`') for item in values);continue
            reasons.append('additional_or_unknown_privilege')
    missing=[]
    for name,rules in expected.items():
        for key in ('select','insert','delete'):
            if actual[name][key]!=rules[key]:reasons.append('table_privilege_mismatch');missing.append(name+':'+key)
        if actual[name]['update_columns']!=set(rules['update_columns']):reasons.append('column_update_mismatch');missing.append(name+':update')
    if roles and roles!='NONE':reasons.append('active_roles_need_review')
    return dict(minimal=not reasons,reasons=sorted(set(reasons)),missing=missing,statement_count=len(grants),roles_resolved=not roles or roles=='NONE',
                contract='schema5_service_table_columns',status='matched' if not reasons else 'unknown_or_mismatch')

def maintenance_findings(grants,database,log_bin,trusted,roles):
    """Problems that would stop schema creation part-way; an empty list means init may start."""
    scope=json.loads((ROOT/'workflow-privileges.json').read_text(encoding='utf-8'))['maintenance_basic_scope']
    needed={table:set(scope['privileges'])|({'UPDATE'} if table in scope.get('update_tables',()) else set()) for table in scope['tables']}
    held={'*':set(),'db':set()};tables={}
    for line in grants:
        match=re.fullmatch(r'GRANT (.+?) ON (.+?) TO .+',line,re.I)
        if not match:continue
        try:parts={part.upper() for part in split_privileges(match[1]) if '(' not in part}
        except ValueError:continue
        if 'ALL PRIVILEGES' in parts or 'ALL' in parts:parts|={'SELECT','INSERT','UPDATE','CREATE','ALTER','INDEX','TRIGGER','REFERENCES','SUPER'}
        target=match[2]
        if target=='*.*':held['*']|=parts
        elif re.fullmatch(r'`'+re.escape(database)+r'`\.\*',target):held['db']|=parts
        else:
            table=re.fullmatch(r'`'+re.escape(database)+r'`\.`([^`]+)`',target)
            if table:tables.setdefault(table[1],set()).update(parts)
    findings=[]
    missing=sorted({p for table,want in needed.items() for p in want-(held['*']|held['db']|tables.get(table,set()))})
    if missing:findings.append('maintenance account lacks '+', '.join(missing)+' on '+database+' (apply: python tools/mysql_grants.py maintenance ...)'+(' ; active roles are not expanded' if roles and roles!='NONE' else ''))
    if log_bin and not trusted and 'SUPER' not in held['*']:
        findings.append('binary logging is on: run SET PERSIST log_bin_trust_function_creators=ON on the MySQL server (or disable binlog) so the schema triggers can be created')
    return findings

def precheck_initialization(maintenance):
    """Read-only checks before any folder or table is created."""
    with transaction(maintenance) as db:
        if db.execute('SHOW TABLES').fetchall():raise ValueError('The MySQL database '+maintenance['database']+' is not empty; init needs a NEW empty database')
        grants=[r[0] for r in db.execute('SHOW GRANTS FOR CURRENT_USER').fetchall()]
        row=db.execute('SELECT @@log_bin AS log_bin,@@log_bin_trust_function_creators AS trusted,CURRENT_ROLE() AS roles').fetchone()
    findings=maintenance_findings(grants,maintenance['database'],int(row['log_bin']),int(row['trusted']),row['roles'])
    if findings:raise ValueError('Initialization not started: '+' | '.join(findings))
