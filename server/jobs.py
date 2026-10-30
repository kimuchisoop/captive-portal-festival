"""Retention, durable outbox processing, monitoring, encrypted backup/restore."""
from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.fernet import Fernet

from app import ROOT, Service, uid, utc
from database import DatabaseError, Connection, connect, load_settings, initialize_schema, table_health
from security import protect_directory


def set_meta(db, key, value):
    db.execute('INSERT INTO meta VALUES (?,?) ON DUPLICATE KEY UPDATE value=VALUES(value)', (key, str(value)))


def notify(db, now, code, message, active=True, severity='warning'):
    old = db.execute('SELECT * FROM notifications WHERE dedupe_key=?',(code,)).fetchone()
    if not active:
        db.execute("UPDATE notifications SET state='resolved',last_seen=? WHERE dedupe_key=? AND state!='resolved'",(now,code))
    elif not old:
        db.execute("INSERT INTO notifications (id,dedupe_key,severity,code,message,state,first_seen,last_seen,acknowledged_by,acknowledged_at) VALUES (?,?,?,?,?,'open',?,?,NULL,NULL)",(uid(),code,severity,code,message,now,now))
    elif old['state'] == 'resolved':
        db.execute("UPDATE notifications SET state='open',last_seen=?,first_seen=?,generation=generation+1,acknowledged_by=NULL,acknowledged_at=NULL WHERE dedupe_key=?",(now,now,code))
    else:
        db.execute('UPDATE notifications SET last_seen=? WHERE dedupe_key=?',(now,code))


def housekeeping(s):
    now = s.now()
    with s.db(True) as db:
        # No browser polling or reconnection can extend this stored absolute deadline.
        expired = db.execute("SELECT * FROM grants WHERE authorization_status='accepted' AND original_expires_at<=?", (now,)).fetchall()
        for grant in expired:
            db.execute("UPDATE grants SET authorization_status='expired',revocation_state='queued',row_version=row_version+1 WHERE id=?", (grant['id'],))
            if not db.execute("SELECT 1 FROM operations WHERE grant_id=? AND action='disconnect'", (grant['id'],)).fetchone():
                db.execute('INSERT INTO operations VALUES (?,?,?,?,?,?,0,?,NULL,?,?)',
                           (uid(), grant['id'], 'disconnect', 'deadline_expired', 'worker', 'queued', now, uid(), grant['delete_after']))
        # This release cannot act on a NAS. Mark the dependency failure, never simulate an ACK.
        rows = db.execute("SELECT * FROM operations WHERE status='queued' AND next_attempt<=?", (now,)).fetchall()
        for op in rows:
            db.execute("UPDATE operations SET status='failed',attempts=attempts+1,last_error_code='adapter_unavailable' WHERE id=?", (op['id'],))
            if op['action'] == 'disconnect':
                db.execute("UPDATE grants SET revocation_state='failed',row_version=row_version+1 WHERE id=?", (op['grant_id'],))
        counts = {}
        for table, field in (('consents','delete_after'),('idempotency','expires_at'),('contexts','expires_at'),
                             ('launches','expires_at'),('sessions','expires_at'),('login_limits','expires_at'),('audit','delete_after')):
            counts[table]=db.execute('SELECT count(*) FROM '+table+' WHERE '+field+'<=?',(now,)).fetchone()[0]
        # User instruction: preserve logs and records. Count expiry candidates, never purge them.
        set_meta(db,'expiry_preview_counts',json.dumps(counts))
    return counts


def monitor(s):
    now = s.now()
    from operations import storage_status,backup_inventory
    inventory=backup_inventory(s,limit=1)
    storage=storage_status(s,backups=inventory)
    free=storage['application_disk_free_bytes']
    from backup_review import MAX_BACKUP_BYTES
    legacy_max=inventory['max_legacy_bytes']
    from operator_features import sample_storage
    sample_storage(s,storage)
    with s.db(True) as db:
        notify(db,now,'retention_paused','ログ・同意記録・バックアップの自動削除は停止中です。保存期限は対象件数の確認だけを行います。')
        notify(db, now, 'adapter_unavailable', 'APとの連携は未接続です。通信許可・切断の完了は確認できません。')
        missing = any(s.config.get(k) is None for k in ('retention_days', 'backup_retention_days', 'audit_retention_days'))
        notify(db, now, 'retention_unconfigured', '同意記録・監査記録・バックアップの保存期間を設定してください。', missing)
        notify(db, now, 'disk_low', '保存先の空き容量が設定した下限を下回っています。', free < s.config['min_free_bytes'], 'critical')
        notify(db,now,'database_size_high','MySQLの推定使用量が設定した警告値に達しています。ログは削除せず容量を確認してください。',storage['database_warning'])
        if storage['backup_bytes_complete'] or storage['backup_warning']:
            notify(db,now,'backup_size_high','バックアップの合計容量が設定した警告値に達しています。ファイルは削除せず保管容量を確認してください。',storage['backup_warning'])
        notify(db,now,'backup_inventory_incomplete','バックアップ容量に読み取れない項目があります。表示値は確認できた分だけです。ファイルを保持して保存先の状態を確認してください。',not storage['backup_bytes_complete'])
        notify(db,now,'capacity_thresholds_unconfigured','MySQL・バックアップ容量の警告値が未設定です。現在の容量は一覧で確認できます。',not storage['thresholds_configured'])
        if storage['backup_bytes_complete'] or legacy_max>=MAX_BACKUP_BYTES*3//4:
            notify(db,now,'backup_legacy_size','従来形式のバックアップが検証上限256MiBに近づいています。削除せず、分割形式の保存・復元を確認してください。',legacy_max>=MAX_BACKUP_BYTES*3//4,'critical' if legacy_max>=MAX_BACKUP_BYTES else 'warning')
        failed = db.execute("SELECT count(*) FROM operations WHERE status='failed'").fetchone()[0]
        notify(db, now, 'operation_failed', '装置連携に未完了の操作があります。対象を確認してください。', bool(failed))
        backup = db.execute("SELECT value FROM meta WHERE name='last_backup_at'").fetchone()
        overdue = not backup or now - int(backup[0]) > s.config['backup_interval_seconds'] * 2
        notify(db, now, 'backup_overdue', '暗号化バックアップが未作成、または最終成功から期限を超えています。', overdue)
        quick = table_health(db)
        notify(db, now, 'database_structure', '必要なMySQLテーブルまたは保存方式を確認できません。受付を停止し復旧手順を参照してください。', not quick, 'critical')


LEGACY_TABLES = ('meta','terms_documents','admins','sessions','login_limits','launches','contexts','consents','grants','operations','idempotency','audit','notifications')
V3_TABLES = LEGACY_TABLES + ('notification_updates','terms_revisions','terms_publications','mfa_settings','mfa_recovery','storage_samples')
TABLES = V3_TABLES + ('backup_checks','support_exports','checklist_runs','checklist_entries')

def snapshot_tables(version):
    return {'2':LEGACY_TABLES,'3':V3_TABLES,'4':TABLES}[version]

def snapshot_schema(version):
    return ROOT/({'2':'schema-v2.sql','3':'schema-v3.sql','4':'schema.sql'}[version])

def inspect_snapshot(payload):
    data = json.loads(payload)
    if not isinstance(data,dict): raise ValueError('Backup snapshot must be an object')
    if data.get('format') != 'festival-wifi-mysql-backup' or data.get('schema_version') not in ('2','3','4'):
        raise ValueError('Unsupported backup format')
    tables=snapshot_tables(data['schema_version'])
    if set(data.get('tables',{})) != set(tables) or set(data.get('columns',{})) != set(tables):
        raise ValueError('Incomplete backup')
    schema=snapshot_schema(data['schema_version'])
    if data.get('schema_sha256') != __import__('hashlib').sha256(schema.read_bytes()).hexdigest():
        raise ValueError('Backup requires its original schema or a dedicated migration')
    for table in tables:
        columns=data['columns'][table]
        if not isinstance(columns,list) or len(columns)!=len(set(columns)):
            raise ValueError('Invalid backup columns')
        for row in data['tables'][table]:
            if not isinstance(row,dict) or set(row)!=set(columns):
                raise ValueError('Invalid backup row')
    return data


def secure_new_file(path, data):
    # OS file permissions are complemented by a private directory ACL on Windows (see install.ps1).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def backup(s):
    from workflow_backup import backup_stream
    return backup_stream(s)
    # Historical legacy writer below is unreachable in this schema-five release.
    if s.config.get('backup_retention_days') is None:
        raise ValueError('Backup retention must be explicitly configured')
    housekeeping(s)
    target=s.home/'backups'; target.mkdir(mode=0o700,exist_ok=True)
    from filesystem_guard import is_link
    if is_link(target): raise ValueError('Linked backup directory')
    key=(s.home/'backup.key').read_bytes()
    snapshot={'format':'festival-wifi-mysql-backup','schema_version':'4','created_at':s.now(),
              'schema_sha256':__import__('hashlib').sha256((ROOT/'schema.sql').read_bytes()).hexdigest(),
              'tables':{},'columns':{}}
    # One repeatable-read transaction gives a consistent InnoDB snapshot across all tables.
    with s.db() as db:
        if not table_health(db): raise ValueError('Unexpected table storage engines')
        for table in TABLES:
            snapshot['columns'][table]=[r['Field'] for r in db.execute('SHOW COLUMNS FROM `'+table+'`').fetchall()]
            snapshot['tables'][table]=db.execute('SELECT * FROM `'+table+'`').fetchall()
    payload=json.dumps(snapshot,ensure_ascii=False,separators=(',',':')).encode('utf-8')
    inspect_snapshot(payload)
    encrypted=Fernet(key).encrypt(payload)
    if Fernet(key).decrypt(encrypted)!=payload: raise ValueError('Backup verification failed')
    filename=target/f'backup-{s.now()}-{uid()}.fernet'
    secure_new_file(filename,encrypted)
    with s.db(True) as db:
        set_meta(db,'last_backup_at',s.now()); s.audit(db,'worker','backup_created')
    return filename


def expire_backups(s):
    # User instruction: keep backup files and logs. No automatic deletion.
    return 0


def run_jobs(s, with_backup=True):
    counts = housekeeping(s)
    failed = False
    if with_backup:
        with s.db() as db:
            last = db.execute("SELECT value FROM meta WHERE name='last_backup_at'").fetchone()
        if not last or s.now() - int(last[0]) >= s.config['backup_interval_seconds']:
            try:
                if s.config.get('backup_format')=='stream-v2':
                    from workflow_backup import backup_stream
                    backup_stream(s)
                else: backup(s)
            except (OSError, ValueError, DatabaseError):
                failed = True
                with s.db(True) as db:
                    notify(db, s.now(), 'backup_failed', '暗号化バックアップの作成に失敗しました。鍵・容量・アクセス権を確認してください。', severity='critical')
            else:
                with s.db(True) as db:
                    notify(db, s.now(), 'backup_failed', '', False)
    expire_backups(s)
    from workflow_alerts import monitor as monitor_workflows
    from archive_repository import prepare_next
    workflow_enabled=s.config.get('workflow_policy',{}).get('approved') is True
    if workflow_enabled: prepare_next(s)
    monitor(s)
    if workflow_enabled: monitor_workflows(s)
    with s.db(True) as db:
        set_meta(db, 'last_job_at', s.now())
    return dict(expiry_preview=counts,automatic_deletion_enabled=False,backup_failed=failed)


def restore(source, key_path, destination, db_settings):
    """Restore to a NEW directory and an EMPTY, separately prepared MySQL database."""
    destination=Path(destination).resolve()
    if destination.exists(): raise ValueError('Restore destination must not exist')
    with Path(source).open('rb') as probe:
        from stream_encryption import MAGIC
        if probe.read(len(MAGIC))==MAGIC:
            from stream_backup import restore_stream
            return restore_stream(source,key_path,destination,db_settings)
    from backup_review import MAX_BACKUP_BYTES
    if Path(source).stat().st_size>MAX_BACKUP_BYTES: raise OverflowError('Legacy restore limit; use streaming format')
    payload=Fernet(Path(key_path).read_bytes()).decrypt(Path(source).read_bytes())
    snapshot=inspect_snapshot(payload)
    raw=connect(db_settings)
    try:
        if Connection(raw).execute('SHOW TABLES').fetchall(): raise ValueError('Restore database must be EMPTY')
    finally: raw.close()
    destination.mkdir(mode=0o700,parents=False); protect_directory(destination)
    secure_new_file(destination/'mysql.json',json.dumps(db_settings).encode())
    secure_new_file(destination/'restore.incomplete',b'review required')
    initialize_schema(db_settings,snapshot_schema(snapshot['schema_version']))
    tables=snapshot_tables(snapshot['schema_version'])
    from database import transaction
    with transaction(db_settings,True) as db:
        for table in tables:
            expected=[r['Field'] for r in db.execute('SHOW COLUMNS FROM `'+table+'`').fetchall()]
            if expected!=snapshot['columns'][table]: raise ValueError('Backup columns do not match schema')
        db.execute('DELETE FROM meta')
        for table in tables:
            if table in ('sessions','login_limits','launches','contexts','idempotency'): continue
            columns=snapshot['columns'][table]
            sql='INSERT INTO `'+table+'` ('+','.join('`'+c+'`' for c in columns)+') VALUES ('+','.join('?' for c in columns)+')'
            for row in snapshot['tables'][table]: db.execute(sql,[row[c] for c in columns])
        db.execute("UPDATE grants SET authorization_status=CASE WHEN authorization_status='revoked' THEN 'revoked' ELSE 'expired' END,observation_state='unknown',revocation_state='failed',row_version=row_version+1")
        db.execute("UPDATE operations SET status='failed',last_error_code='restore_requires_reconciliation'")
        set_meta(db,'restored_requires_review','true')
        if snapshot['schema_version'] in ('3','4'):
            # Restored MFA material cannot be decrypted with new local keys. Require deliberate re-enrollment.
            db.execute('UPDATE mfa_settings SET needs_reset=1 WHERE enabled=1')
    if snapshot['schema_version'] in ('2','3'):
        from migrations import upgrade_to_v4
        upgrade_to_v4(db_settings,destination)
    (destination/'restore.incomplete').unlink()
    return destination
