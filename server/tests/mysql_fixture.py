"""Only a disposable MySQL instance with its own datadir; preserve all test artifacts."""
import json
import os
import secrets
import sys
from pathlib import Path
import mysql.connector

def credentials():
    path=Path(os.environ['WIFI_TEST_MYSQL_CONFIG']).resolve()
    c=json.loads(path.read_text(encoding='utf-8'))
    if c.get('test_only') is not True or c.get('host')!='127.0.0.1' or type(c.get('port')) is not int:
        raise ValueError('Tests require an explicitly disposable loopback MySQL instance')
    if not c.get('maintenance_user') or c['maintenance_user']==c.get('user') or not c.get('maintenance_password'):
        raise ValueError('Tests require a separate maintenance account (maintenance_user/maintenance_password)')
    raw=mysql.connector.connect(**{k:c[k] for k in ('host','port','user','password')},use_pure=True)
    cursor=raw.cursor();cursor.execute('SELECT @@datadir');data=cursor.fetchone()[0];cursor.close();raw.close()
    # A container reports its own datadir (e.g. /var/lib/mysql/); state it explicitly in the config.
    expected=c['datadir'] if 'datadir' in c else str((path.parent/'data').resolve())
    actual=data if 'datadir' in c else str(Path(data).resolve())
    if actual.rstrip('/'+chr(92))!=expected.rstrip('/'+chr(92)):
        raise ValueError('Test MySQL datadir mismatch; refusing to use existing service')
    return c,path.parent

def new_database():
    c,_=credentials()
    name='sff_test_'+secrets.token_hex(8)
    raw=mysql.connector.connect(**{k:c[k] for k in ('host','port','user','password')},use_pure=True)
    try:
        cursor=raw.cursor();cursor.execute('CREATE DATABASE `'+name+'` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin');cursor.close()
    finally: raw.close()
    return {**{k:c[k] for k in ('host','port','user','password')},'database':name}

def maintenance_file(settings):
    """Protected maintenance settings for the same database, written to a NEW private folder."""
    c,parent=credentials()
    from security import protect_directory
    from jobs import secure_new_file
    folder=parent/'maintenance-settings'/secrets.token_hex(12);folder.mkdir(parents=True);protect_directory(folder)
    path=folder/'maintenance.json'
    secure_new_file(path,json.dumps({**settings,'user':c['maintenance_user'],'password':c['maintenance_password']}).encode())
    return path

def init_home(home,sample=False,settings=None):
    from workflow_cli import initialize
    settings=settings or new_database()
    return initialize(home,sample,db_settings=settings,maintenance_file=maintenance_file(settings))

class PreservedDirectory:
    def __init__(self):
        _,parent=credentials()
        path=parent/'test-artifacts'/secrets.token_hex(12)
        path.mkdir(parents=True)
        from security import protect_directory
        protect_directory(path)
        self.name=str(path)
    def cleanup(self):
        # No automatic removal: logs and test data remain available for review.
        pass
