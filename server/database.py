"""MySQL only. InnoDB transactions and a per-database application write lock."""
import hashlib
import json
import os
import re
import threading
import time
from contextlib import contextmanager
from pathlib import Path
import mysql.connector
from mysql.connector import Error as DatabaseError

class Row(dict):
    def __getitem__(self, key):
        return list(self.values())[key] if isinstance(key, int) else super().__getitem__(key)

class Result:
    def __init__(self, rows, rowcount):
        self.rows, self.rowcount = iter(rows), rowcount
    def fetchone(self): return next(self.rows, None)
    def fetchall(self): return list(self.rows)

class Connection:
    def __init__(self, raw): self.raw = raw
    def executemany(self, sql, rows):
        cursor=self.raw.cursor(buffered=True)
        try:
            cursor.executemany(sql.replace('?', '%s'),rows)
            return Result([],cursor.rowcount)
        finally:cursor.close()
    def execute(self, sql, params=()):
        cursor = self.raw.cursor(dictionary=True, buffered=True)
        try:
            cursor.execute(sql.replace('?', '%s'), tuple(params))
            return Result([Row(r) for r in cursor.fetchall()] if cursor.with_rows else [], cursor.rowcount)
        finally: cursor.close()

def load_settings(path):
    c = json.loads(Path(path).read_text(encoding='utf-8'))
    return validate_settings(c)

def validate_settings(c):
    if not isinstance(c,dict): raise ValueError('MySQL settings must be an object')
    if set(c) - {'host','port','user','password','database','ssl_ca'}: raise ValueError('Unsupported MySQL option')
    if any(not isinstance(c.get(k), str) or not c[k] for k in ('host','user','password','database')): raise ValueError('Incomplete MySQL settings')
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,63}', c['database']): raise ValueError('Invalid database name')
    if type(c.get('port')) is not int or not 1 <= c['port'] <= 65535: raise ValueError('Invalid port')
    if c['host'] not in ('127.0.0.1','localhost') and not c.get('ssl_ca'): raise ValueError('Remote MySQL requires verified TLS')
    return c

def connect(c):
    options = dict(host=c['host'],port=c['port'],user=c['user'],password=c['password'],database=c['database'],
                   charset='utf8mb4',collation='utf8mb4_bin',autocommit=False,connection_timeout=5,
                   read_timeout=15,write_timeout=15,use_pure=True,allow_local_infile=False)
    if c.get('ssl_ca'): options.update(ssl_ca=c['ssl_ca'],ssl_verify_cert=True,ssl_verify_identity=True)
    else: options['ssl_disabled'] = False
    raw = mysql.connector.connect(**options)
    if raw.server_version < (8,0,16):
        raw.close(); raise ValueError('MySQL 8.0.16+ required')
    return raw

# Connecting (TLS and authentication, in pure Python) costs about 35 queries, so finished
# transactions hand their connection back for reuse. A returned connection is reset on the
# server (session variables, user locks, temporary tables) and given the connect-time
# settings again; any error, failed reset or age limit closes it instead. Idle connections are
# also capped in total, so targets no longer used (other accounts, test databases) do not pile up.
POOL_IDLE_LIMIT = 8
POOL_TOTAL_IDLE_LIMIT = 16
POOL_MAX_AGE_SECONDS = 300
SESSION_SETTINGS = "SET NAMES utf8mb4 COLLATE utf8mb4_bin, autocommit=0"
_pool = {}
_pool_lock = threading.Lock()

def _pool_key(c):
    # Different accounts or targets never share a connection; a forked process starts empty.
    return os.getpid(), hashlib.sha256(json.dumps(c, sort_keys=True).encode()).hexdigest()

def _close(raw):
    try: raw.close()
    except Exception: pass

def _checkout(c):
    key = _pool_key(c)
    while True:
        with _pool_lock:
            idle = _pool.get(key)
            entry = idle.pop() if idle else None
        if entry is None:
            return key, connect(c), time.monotonic()
        raw, created = entry
        if time.monotonic() - created < POOL_MAX_AGE_SECONDS:
            try:
                raw.ping(reconnect=False)
                return key, raw, created
            except Exception: pass
        _close(raw)

def _checkin(key, raw, created):
    if time.monotonic() - created >= POOL_MAX_AGE_SECONDS: return _close(raw)
    try:
        if not raw.cmd_reset_connection(): return _close(raw)
        cursor = raw.cursor(); cursor.execute(SESSION_SETTINGS); cursor.close()
    except Exception: return _close(raw)
    evicted = []
    with _pool_lock:
        idle = _pool.pop(key, [])
        if len(idle) < POOL_IDLE_LIMIT: idle.append((raw, created))
        else: evicted.append((raw, created))
        _pool[key] = idle  # most recently returned target last
        total = sum(len(entries) for entries in _pool.values())
        for other in list(_pool):
            while total > POOL_TOTAL_IDLE_LIMIT and _pool[other]:
                evicted.append(_pool[other].pop(0)); total -= 1
            if not _pool[other]: del _pool[other]
    for old, _ in evicted: _close(old)

def clear_pool():
    with _pool_lock:
        entries = [entry for idle in _pool.values() for entry in idle]; _pool.clear()
    for raw, _ in entries: _close(raw)

@contextmanager
def transaction(c, write=False):
    key, raw, created = _checkout(c); db = Connection(raw); locked = False; reusable = False
    lock = 'festival-wifi:' + hashlib.sha256(c['database'].encode()).hexdigest()[:32]
    try:
        if write:
            locked = db.execute('SELECT GET_LOCK(?,10) AS acquired',(lock,)).fetchone()[0] == 1
            if not locked: raise DatabaseError('Write lock timeout')
        raw.start_transaction(isolation_level='REPEATABLE READ', readonly=not write)
        yield db
        raw.commit() if write else raw.rollback()
        reusable = True
    except BaseException:
        raw.rollback(); raise
    finally:
        try:
            if locked: db.execute('SELECT RELEASE_LOCK(?)',(lock,))
        except BaseException:
            reusable = False; raise
        finally:
            _checkin(key, raw, created) if reusable else _close(raw)

def initialize_schema(c, schema_file):
    raw = connect(c); db = Connection(raw)
    try:
        if db.execute('SHOW TABLES').fetchall(): raise ValueError('An EMPTY dedicated MySQL database is required')
        # Schema comments can contain semicolons. Remove full-line comments
        # before splitting these simple, repository-owned DDL statements.
        schema = '\n'.join(line for line in Path(schema_file).read_text(encoding='utf-8').splitlines()
                           if not line.lstrip().startswith('--'))
        for statement in schema.split(';'):
            if statement.strip(): db.execute(statement)
        raw.commit()
    finally: raw.close()

def table_health(db):
    rows = db.execute("SELECT TABLE_NAME,ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE'").fetchall()
    from workflow_database import TABLES
    return {r['TABLE_NAME'] for r in rows} == set(TABLES) and all(r['ENGINE'] == 'InnoDB' for r in rows)
