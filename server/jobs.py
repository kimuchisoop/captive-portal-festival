"""Retention, durable outbox processing, monitoring and scheduled encrypted backups."""
from __future__ import annotations

import json
import os

from app import uid
from database import DatabaseError, table_health


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
    network = getattr(s, 'network', None)
    if network:
        # Guest grants go to core-rt: expiry removals and retries the serve process could not finish.
        from network_access import process_due
        process_due(s)
    with s.db(True) as db:
        # Nothing else can act on a NAS. Mark the dependency failure, never simulate an ACK.
        rows = db.execute("SELECT o.* FROM operations o LEFT JOIN grants g ON g.id=o.grant_id WHERE o.status='queued' AND o.next_attempt<=?"
                          + (" AND (g.connection_ref IS NULL OR g.connection_ref NOT LIKE ?)" if network else ''),
                          (now, 'ipv4:%') if network else (now,)).fetchall()
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
        failed = db.execute("SELECT count(*) FROM operations WHERE status='failed'").fetchone()[0]
        notify(db, now, 'operation_failed', '装置連携に未完了の操作があります。対象を確認してください。', bool(failed))
        backup = db.execute("SELECT value FROM meta WHERE name='last_backup_at'").fetchone()
        overdue = not backup or now - int(backup[0]) > s.config['backup_interval_seconds'] * 2
        notify(db, now, 'backup_overdue', '暗号化バックアップが未作成、または最終成功から期限を超えています。', overdue)
        quick = table_health(db)
        notify(db, now, 'database_structure', '必要なMySQLテーブルまたは保存方式を確認できません。受付を停止し復旧手順を参照してください。', not quick, 'critical')


def secure_new_file(path, data):
    # OS file permissions are complemented by a private directory ACL on Windows (see install.ps1).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


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
                from workflow_backup import backup_stream
                backup_stream(s)
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
