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
    if c.get('test_only') is not True or c.get('host')!='127.0.0.1' or c.get('port')!=13307:
        raise ValueError('Tests require the explicitly disposable loopback MySQL instance on 13307')
    raw=mysql.connector.connect(**{k:c[k] for k in ('host','port','user','password')},use_pure=True)
    cursor=raw.cursor();cursor.execute('SELECT @@datadir');data=cursor.fetchone()[0];cursor.close();raw.close()
    if Path(data).resolve() != (path.parent/'data').resolve():
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
