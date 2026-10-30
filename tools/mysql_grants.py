"""Print MySQL GRANT statements generated from server/workflow-privileges.json. Nothing is executed.

Usage:
  python tools/mysql_grants.py maintenance --database app_db --user app_maintenance --host 127.0.0.1
  python tools/mysql_grants.py runtime     --database app_db --user app_service     --host 127.0.0.1

Order: create the empty DB and both accounts, apply the maintenance grants, run `init` with the
maintenance account, then apply the runtime grants (column grants need the tables to exist).
Passwords are never generated or printed; set them with CREATE USER / ALTER USER yourself.
"""
from pathlib import Path
import argparse,json,re

ROOT=Path(__file__).resolve().parents[1]/'server'
NAME=re.compile(r'[A-Za-z_][A-Za-z0-9_$]{0,63}')

def load():
    return json.loads((ROOT/'workflow-privileges.json').read_text(encoding='utf-8'))

def account(user,host):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',user) or not re.fullmatch(r'[A-Za-z0-9_.:%-]{1,255}',host):
        raise ValueError('Unsupported account name or host')
    return "'"+user+"'@'"+host+"'"

def identifier(value):
    if not NAME.fullmatch(value):raise ValueError('Unsupported identifier: '+value)
    return '`'+value+'`'

def runtime_statements(database,user,host,contract=None):
    contract=contract or load();target=account(user,host);statements=[]
    for rule in contract['runtime']:
        privileges=[name for name in ('select','insert','delete') if rule[name]]
        privileges=[name.upper() for name in privileges]
        if rule['update_columns']:
            privileges.append('UPDATE ('+', '.join(identifier(c) for c in rule['update_columns'])+')')
        if privileges:
            statements.append('GRANT '+', '.join(privileges)+' ON '+identifier(database)+'.'+identifier(rule['table'])+' TO '+target+';')
    return statements

def maintenance_statements(database,user,host,contract=None):
    contract=contract or load();scope=contract['maintenance_basic_scope'];target=account(user,host)
    statements=[]
    for table in scope['tables']:
        privileges=list(scope['privileges'])+(['UPDATE'] if table in scope.get('update_tables',()) else [])
        statements.append('GRANT '+', '.join(privileges)+' ON '+identifier(database)+'.'+identifier(table)+' TO '+target+';')
    return statements

def main():
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('profile',choices=('runtime','maintenance'))
    parser.add_argument('--database',required=True);parser.add_argument('--user',required=True);parser.add_argument('--host',required=True)
    args=parser.parse_args();identifier(args.database)
    build=runtime_statements if args.profile=='runtime' else maintenance_statements
    print('-- '+args.profile+' grants for '+account(args.user,args.host)+' on '+identifier(args.database)+' (generated, review before use)')
    print('\n'.join(build(args.database,args.user,args.host)))

if __name__=='__main__':main()
