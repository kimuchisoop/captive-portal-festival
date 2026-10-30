"""Read-only operational inspection. Never changes MySQL grants or removes records."""
from __future__ import annotations

import json
import heapq
import os
import re
import shutil
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import g, jsonify, request
from database import Connection, DatabaseError, connect

BACKUP_NAME = re.compile(r'^backup-(\d{1,12})-([0-9a-f-]{36})\.(?:fernet|sffbackup)$')
ACTIONS = {
    'event_information_plan_saved':'案内情報の変更案を保存','event_information_change_requested':'案内情報の変更要求','event_information_changed':'案内情報を変更',
    'recovery_kit_created':'暗号化した復旧用一式を作成',
    'capacity_change_requested':'容量警告の変更要求','capacity_changed':'容量警告を変更',
    'login':'ログイン','login_failed':'ログイン失敗','logout':'ログアウト',
    'consent_created':'同意保存','consents_export':'同意記録の出力',
    'revoke_requested':'受付側の失効要求','notification_acknowledged':'通知を確認',
    'backup_created':'バックアップ作成','admin_created':'管理者を追加',
    'admin_changed':'管理者を変更','local_launch_created':'確認用リンクを発行',
    'diagnostic_run':'MySQL接続・権限の診断',
    'notification_handover':'通知の対応を引き継ぎ','terms_draft_saved':'規約の下書きを保存',
    'terms_published_local':'規約をローカル適用','mfa_enrolled':'追加認証を登録',
    'mfa_reset':'追加認証を復旧','mfa_failed':'追加認証の失敗','mfa_recovery_used':'復旧コードを使用',
    'backup_decrypt_checked':'バックアップを復号検証','backup_restore_checked':'バックアップを復元検証',
    'support_bundle_created':'障害調査資料を作成','support_bundle_downloaded':'障害調査資料を取得',
    'checklist_created':'当日チェックを開始','checklist_updated':'当日チェックを記録',
    'consent_archive_failed':'固定CSVの準備失敗を記録',
    'consent_archive_page_generated':'固定CSVのページを生成',
    'consent_archive_queued':'固定CSVの準備を受付',
    'consent_archive_ready':'固定CSVの準備完了を記録',
    'consent_archive_recovery_released':'復旧後の固定CSVの照合を解除',
    'event_plan_apply_requested':'確認済み変更案の適用を要求',
    'event_plan_observed':'変更案の適用結果を照合',
    'event_plan_review_recorded':'変更案の別担当確認を記録',
    'event_plan_review_requested':'変更案の別担当確認を依頼',
    'event_plan_withdrawn':'変更案を取り下げ',
    'schema5_recovery_released':'形式5の復旧後確認を解除',
    'schema5_restored':'形式5の復元と安全化を記録',
    'workflow_notification_generation_changed':'作業通知の再発を記録',
    'workflow_notification_opened':'作業通知を開始',
    'workflow_notification_resolved':'作業通知の解消を記録',
    'workflow_policy_config_written':'ワークフロー設定の書込みを記録',
    'workflow_policy_plan_prepared':'ワークフロー設定案を準備',
    'workflow_policy_reconciled_not_written':'ワークフロー設定の未反映を照合',
    'workflow_policy_reconciled_written':'ワークフロー設定の反映を照合',
}
ACTORS = {'local_cli':'サーバー端末','worker':'定期処理','visitor':'来場者','anonymous':'ログイン前'}

def utc(value):
    return datetime.fromtimestamp(value,timezone.utc).isoformat().replace('+00:00','Z')

def query_time(value):
    if not value:
        return None
    if not isinstance(value,str) or len(value)>32 or not value.endswith('Z'):
        raise ValueError('invalid UTC date')
    return int(datetime.fromisoformat(value.replace('Z','+00:00')).timestamp())

def audit_search(s, args):
    allowed={'from','until','actor','action','before_time','before_id','limit'}
    if set(args)-allowed:
        raise ValueError('unknown filter')
    start,end=query_time(args.get('from')),query_time(args.get('until'))
    if start is not None and end is not None and start>=end:
        raise ValueError('invalid range')
    limit=int(args.get('limit','50'))
    if not 1<=limit<=100:
        raise ValueError('invalid limit')
    clauses=[]; params=[]
    for name,op,value in [('created_at','>=',start),('created_at','<',end)]:
        if value is not None: clauses.append('a.'+name+op+'?');params.append(value)
    for name in ('actor','action'):
        value=args.get(name,'')
        if value:
            if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,80}',value): raise ValueError('invalid filter')
            clauses.append('a.'+name+'=?');params.append(value)
    before_time=args.get('before_time');before_id=args.get('before_id')
    if bool(before_time)!=bool(before_id): raise ValueError('incomplete cursor')
    if before_id:
        uuid.UUID(before_id); before=int(before_time)
        if before<0: raise ValueError('invalid cursor')
        clauses.append('(a.created_at<? OR (a.created_at=? AND a.id<?))')
        params.extend((before,before,before_id))
    where=' WHERE '+' AND '.join(clauses) if clauses else ''
    with s.db() as db:
        rows=db.execute('SELECT a.id,a.actor,u.username,a.action,a.object_id,a.created_at FROM audit a '
                        'LEFT JOIN admins u ON a.actor=u.id'+where+
                        ' ORDER BY a.created_at DESC,a.id DESC LIMIT ?',params+[limit+1]).fetchall()
        users=db.execute('SELECT id,username,enabled FROM admins ORDER BY username').fetchall()
    more=len(rows)>limit;rows=rows[:limit]
    items=[dict(id=r['id'],actor=r['actor'],actor_label=r['username'] or ACTORS.get(r['actor'],'未登録の担当者'),
                action=r['action'],action_label=ACTIONS.get(r['action'],r['action']),
                object_id=r['object_id'],created_at_utc=utc(r['created_at'])) for r in rows]
    cursor={'before_time':str(rows[-1]['created_at']),'before_id':rows[-1]['id']} if more else None
    return dict(items=items,next_cursor=cursor,limit=limit,
                actors=[{'id':k,'label':v} for k,v in ACTORS.items()]+
                       [{'id':u['id'],'label':u['username']+('（無効）' if not u['enabled'] else '')} for u in users],
                actions=[{'id':k,'label':v} for k,v in ACTIONS.items()],automatic_deletion_enabled=False)

def backup_inventory(s, before=None, limit=50):
    if type(limit) is not int or not 1<=limit<=100: raise ValueError('invalid limit')
    if before and not BACKUP_NAME.fullmatch(before): raise ValueError('invalid cursor')
    if before: uuid.UUID(BACKUP_NAME.fullmatch(before)[2])
    directory=s.home/'backups'
    totals=dict(total_files=0,completed_bytes=0,partial_files=0,partial_bytes=0,
                other_regular_files=0,other_regular_bytes=0,ignored_entries=0,
                unreadable_entries=0,directory_scan_complete=True,max_legacy_bytes=0)
    cursor=None
    if before:
        match=BACKUP_NAME.fullmatch(before);cursor=(int(match[1]),match[2],before)

    def candidates():
        try:directory_info=directory.lstat()
        except FileNotFoundError:return
        except OSError:
            totals['directory_scan_complete']=False;return
        if (stat.S_ISLNK(directory_info.st_mode) or
            getattr(directory_info,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0x400)):
            raise ValueError('backup directory must not be a link')
        if not stat.S_ISDIR(directory_info.st_mode):
            totals['directory_scan_complete']=False;return
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:info=entry.stat(follow_symlinks=False)
                    except OSError:
                        totals['unreadable_entries']+=1;continue
                    if (not stat.S_ISREG(info.st_mode) or
                        getattr(info,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0x400)):
                        totals['ignored_entries']+=1;continue
                    # Preserve the old *.fernet warning scope, including renamed files.
                    if entry.name.endswith('.fernet'):
                        totals['max_legacy_bytes']=max(totals['max_legacy_bytes'],info.st_size)
                    partial=entry.name.endswith('.partial')
                    match=BACKUP_NAME.fullmatch(entry.name[:-8] if partial else entry.name)
                    try:
                        if not match:raise ValueError('Other regular file')
                        uuid.UUID(match[2]);created=int(match[1]);created_utc=utc(created)
                    except (ValueError,OverflowError,OSError):
                        totals['other_regular_files']+=1;totals['other_regular_bytes']+=info.st_size;continue
                    if partial:
                        totals['partial_files']+=1;totals['partial_bytes']+=info.st_size;continue
                    totals['total_files']+=1;totals['completed_bytes']+=info.st_size
                    order=(created,match[2],entry.name)
                    if cursor is None or order<cursor:
                        yield dict(filename=entry.name,created_at_utc=created_utc,bytes=info.st_size,
                                   verification='not_checked',_sort=order)
        except OSError:
            totals['directory_scan_complete']=False

    # Iterate all entries for totals, retaining only the requested page plus its lookahead.
    files=heapq.nlargest(limit+1,candidates(),key=lambda item:item['_sort'])
    page=files[:limit]
    items=[{k:v for k,v in f.items() if k!='_sort'} for f in page]
    total_bytes=totals['completed_bytes']+totals['partial_bytes']+totals['other_regular_bytes']
    return dict(items=items,next_cursor=page[-1]['filename'] if len(files)>limit else None,
                **totals,total_bytes=total_bytes,
                total_bytes_complete=totals['directory_scan_complete'] and totals['unreadable_entries']==0,
                automatic_deletion_enabled=False)

def storage_status(s, *, backups=None):
    with s.db() as db:
        rows=db.execute('SELECT TABLE_NAME,TABLE_ROWS,DATA_LENGTH,INDEX_LENGTH FROM information_schema.TABLES '
                        'WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE=\'BASE TABLE\' ORDER BY TABLE_NAME').fetchall()
    tables=[dict(name=r['TABLE_NAME'],estimated_rows=int(r['TABLE_ROWS'] or 0),
                 allocated_bytes=int(r['DATA_LENGTH'] or 0)+int(r['INDEX_LENGTH'] or 0)) for r in rows]
    if backups is None:backups=backup_inventory(s,limit=1)
    disk=shutil.disk_usage(s.home)
    db_bytes=sum(r['allocated_bytes'] for r in tables)
    db_limit=s.config.get('db_warning_bytes');backup_limit=s.config.get('backup_warning_bytes')
    return dict(checked_at_utc=utc(s.now()),database_allocated_bytes=db_bytes,database_size_is_estimate=True,
                tables=tables,database_disk_free_bytes=None,
                backup_files=backups['total_files'],backup_bytes=backups['total_bytes'],
                backup_completed_bytes=backups['completed_bytes'],
                backup_partial_files=backups['partial_files'],backup_partial_bytes=backups['partial_bytes'],
                backup_other_regular_files=backups['other_regular_files'],backup_other_regular_bytes=backups['other_regular_bytes'],
                backup_unreadable_entries=backups['unreadable_entries'],backup_bytes_complete=backups['total_bytes_complete'],
                application_disk_free_bytes=disk.free,application_disk_total_bytes=disk.total,
                db_warning_bytes=db_limit,backup_warning_bytes=backup_limit,
                database_warning=db_limit is not None and db_bytes>=db_limit,
                backup_warning=backup_limit is not None and backups['total_bytes']>=backup_limit,
                backup_warning_unknown=backup_limit is not None and not backups['total_bytes_complete'] and backups['total_bytes']<backup_limit,
                thresholds_configured=db_limit is not None and backup_limit is not None,
                automatic_deletion_enabled=False)

def inspect_grants(grants,database,roles):
    from workflow_database import inspect_grants as inspect_table_contract
    return inspect_table_contract(grants,database,roles)


def mysql_diagnostic(settings):
    checks=[]
    def add(code,status,label,detail): checks.append(dict(code=code,status=status,label=label,detail=detail))
    raw=None;connected=False
    try:
        raw=connect(settings);db=Connection(raw);connected=True
        add('connection','pass','MySQL接続','接続できました。')
        session=db.execute("SHOW SESSION STATUS LIKE 'Ssl_cipher'").fetchone()
        encrypted=bool(session and session['Value'])
        add('tls_transport','pass' if encrypted else 'fail','通信の暗号化',
            '暗号化されています。' if encrypted else '暗号化を確認できません。')
        verified=bool(settings.get('ssl_ca'))
        add('tls_identity','pass' if verified else 'warning','接続先証明書の検証',
            'CAとホスト名の検証を有効にした接続です。' if verified else 'ローカル接続では証明書の本人確認が未設定です。')
        grants=[r[0] for r in db.execute('SHOW GRANTS FOR CURRENT_USER').fetchall()]
        roles=db.execute('SELECT CURRENT_ROLE() AS roles').fetchone()[0]
        result=inspect_grants(grants,settings['database'],roles)
        add('privileges','pass' if result['minimal'] else 'warning','専用利用者の権限',
            '専用DBの表・列単位の権限契約との一致を確認しました。' if result['minimal'] else '追加権限・役割・権限不足の確認が必要です。権限変更は行っていません。')
        return dict(checks=checks,privilege_review=result,connected=True,
                    target={'host':settings['host'],'port':settings['port'],'database':settings['database'],'user':settings['user']},
                    mutation_performed=False,production_ready=False)
    except (DatabaseError,OSError,ValueError):
        add('inspection' if connected else 'connection','fail','診断の完了' if connected else 'MySQL接続',
            '確認を完了できません。接続先・利用者・TLS設定を確認してください。')
        return dict(checks=checks,connected=connected,mutation_performed=False,production_ready=False)
    finally:
        if raw is not None: raw.close()

def register_operations(app,s,auth,body):
    @app.post('/v1/admin/preflight')
    @auth('admin','settings')
    def preflight_api():
        body(())
        from preflight import inspect_home
        return jsonify(inspect_home(s.home))

    from app import ApiError,uid
    @app.get('/v1/admin/audit')
    @auth('admin','settings')
    def audit_api():
        try: return jsonify(audit_search(s,request.args))
        except (ValueError,TypeError,OverflowError): raise ApiError('audit_query_invalid',400,'日時・絞り込み条件を確認してください。')

    @app.get('/v1/admin/storage')
    @auth('admin','read')
    def storage_api(): return jsonify(storage_status(s))

    @app.get('/v1/admin/backups')
    @auth('admin','records')
    def backups_api():
        try:
            if set(request.args)-{'before','limit'}: raise ValueError()
            result=backup_inventory(s,request.args.get('before'),int(request.args.get('limit','50')))
            from backup_review import verification_summary
            with s.db() as db:
                for item in result['items']:
                    try: item['checks']=verification_summary(s,item,db)
                    except OSError: item['checks']={'decrypt':None,'restore':None}
                    passed=[stage for stage,c in item['checks'].items() if c and c['status']=='passed']
                    item['verification']='restore_checked' if 'restore' in passed else 'decrypt_checked' if 'decrypt' in passed else 'not_checked'
            return jsonify(result)
        except (ValueError,OverflowError): raise ApiError('backup_query_invalid',400)

    @app.post('/v1/admin/diagnostics')
    @auth('admin','settings')
    def diagnostic_api():
        body(())
        result=mysql_diagnostic(s.db_settings);result['report_id']=uid();result['checked_at_utc']=utc(s.now())
        directory=s.home/'diagnostics';directory.mkdir(mode=0o700,exist_ok=True)
        if directory.is_symlink(): raise ApiError('diagnostic_storage_invalid',503)
        from jobs import secure_new_file
        secure_new_file(directory/(result['report_id']+'.json'),json.dumps(result,ensure_ascii=False).encode())
        try:
            with s.db(True) as db: s.audit(db,g.session['owner_id'],'diagnostic_run',result['report_id'])
            result['audit_saved']=True
        except DatabaseError: result['audit_saved']=False
        return jsonify(result)

    @app.get('/v1/admin/ap-readiness')
    @auth('admin','settings')
    def ap_api():
        from ap_profile import inspect_profile
        return jsonify(inspect_profile(s.home/'device-profile.json'))
