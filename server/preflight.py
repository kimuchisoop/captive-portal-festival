"""Collect launch problems without printing secrets or changing network/database settings."""
import importlib.metadata,json,os,stat,subprocess
from pathlib import Path
from cryptography.fernet import Fernet
from database import load_settings,transaction,table_health
from filesystem_guard import is_link

def private_paths(paths):
    if os.name!='nt': return all((p.stat().st_mode & 0o077)==0 for p in paths)
    # Pass paths as environment data, never interpolate them into executable shell text.
    import base64
    from security import windows_sid
    script=r'''$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; $allowed=@($env:SFF_ACL_SID,'S-1-5-18','S-1-5-32-544'); $ok=$true; foreach($p in ($env:SFF_ACL_PATHS|ConvertFrom-Json)) { $acl=Get-Acl -LiteralPath $p; if($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -notin $allowed){$ok=$false}; foreach($r in $acl.Access) { $sid=$r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value; if($r.AccessControlType -eq 'Allow' -and $sid -notin $allowed -and $sid -ne 'S-1-3-4') { $ok=$false } } }; if($ok){'private'}else{'broad'}'''
    encoded=base64.b64encode(script.encode('utf-16-le')).decode()
    environment=dict(os.environ,SFF_ACL_PATHS=json.dumps([str(p) for p in paths]),SFF_ACL_SID=windows_sid())
    # A pwsh parent may supply PS7 modules which Windows PowerShell cannot load.
    environment={k:v for k,v in environment.items() if k.lower()!='psmodulepath'}
    # Compare the ASCII result as bytes; localized stderr is not necessarily UTF-8.
    result=subprocess.run(['powershell','-NoProfile','-NonInteractive','-EncodedCommand',encoded],env=environment,capture_output=True,timeout=25)
    return result.returncode==0 and result.stdout.strip()==b'private'

def inspect_home(home,online=True,package_check=True):
    from app import Service
    home=Path(home).resolve();checks=[]
    def add(code,status,label,detail): checks.append(dict(code=code,status=status,label=label,detail=detail))
    required=['config.json','mysql.json','session.key','backup.key','mfa.key','terms.ja.txt','terms.en.txt']
    existing=[]
    for name in required:
        path=home/name
        if is_link(path) or not path.is_file(): add('file_'+name,'fail',name,'通常のファイルを確認できません。')
        else: existing.append(path)
    incomplete=any((home/name).exists() or is_link(home/name) for name in ('initialization.incomplete','restore.incomplete','upgrade.incomplete','policy-apply.incomplete'))
    add('incomplete','fail' if incomplete else 'pass','初期化・移行・復元・設定適用の状態','未完了マーカーがあります。' if incomplete else '未完了マーカーはありません。')
    config=None;settings=None
    try:
        config=json.loads((home/'config.json').read_text(encoding='utf-8'))
        if not isinstance(config,dict): raise ValueError()
        candidate=Service.__new__(Service);candidate.home=home;candidate.config=config;candidate.validate_config()
        add('configuration','pass','受付・利用期間・保存方針','設定の形式と矛盾の検査を通過しました。')
    except Exception: add('configuration','fail','受付・利用期間・保存方針','設定の不足・利用期間・許可されない本番設定などを確認してください。')
    try: settings=load_settings(home/'mysql.json');add('mysql_settings','pass','MySQL接続設定','接続情報の形式を確認しました。値は表示しません。')
    except Exception: add('mysql_settings','fail','MySQL接続設定','接続情報の不足またはTLS設定を確認してください。')
    for name in ('session.key','backup.key','mfa.key'):
        try:
            data=(home/name).read_bytes()
            if name=='session.key':
                if len(data)!=32: raise ValueError()
            else: Fernet(data)
            add('key_'+name,'pass',name,'鍵の形式を確認しました。内容は表示しません。')
        except Exception: add('key_'+name,'fail',name,'鍵の存在・形式・読み取り権限を確認してください。')
    try:
        valid=not home.is_symlink() and private_paths([home]+existing)
        add('permissions','pass' if valid else 'fail','保存先・秘密ファイルのアクセス権','本人・SYSTEM・管理者以外の許可がないことを確認しました。' if valid else '広いアクセス許可、または権限検査の失敗があります。')
    except Exception: add('permissions','fail','保存先・秘密ファイルのアクセス権','アクセス権を確認できません。権限を自動変更しません。')
    for directory in ('backups','runtime','diagnostics','support-reports','configuration-history'):
        if is_link(home/directory): add('directory_'+directory,'fail',directory,'リンクされた保存先は使用できません。')
    # OS access() is a read-only capability check, not a guarantee against later changes.
    add('writable','pass' if os.access(home,os.W_OK) else 'fail','保存先への書き込み','現在のOS利用者の書き込み可否を確認しました。')
    root=Path(__file__).parent
    try:
        for line in (root/'requirements.txt').read_text().splitlines():
            name,version=line.split('==')
            if importlib.metadata.version(name)!=version: raise ValueError()
        add('dependencies','pass','依存ライブラリ','固定した12パッケージの版が一致しています。')
    except Exception: add('dependencies','fail','依存ライブラリ','不足または版の不一致があります。専用の導入手順を実行してください。')
    if package_check:
        from stream_backup import file_hash
        try:
            manifest=json.loads((root/'release-manifest.json').read_text(encoding='utf-8'))
            if not all(file_hash(root/name)==value for name,value in manifest['files'].items()): raise ValueError()
            add('package','pass','配布ファイルの照合','配布時のSHA256に一致しました。署名ではありません。')
        except Exception: add('package','fail','配布ファイルの照合','欠落・変更・照合情報の不足があります。配布物を確認してください。')
    if online and settings:
        try:
            with transaction(settings) as db:
                version=db.execute("SELECT value FROM meta WHERE name='schema_version'").fetchone()
                if not table_health(db) or not version or version[0]!='5': raise ValueError()
                from workflow_generation import OpsContext,require_runtime_ready
                require_runtime_ready(OpsContext(home),db)
            add('database','pass','MySQL接続・保存構造','読み取り接続とDB形式5・31テーブルを確認しました。')
        except Exception: add('database','fail','MySQL接続・保存構造','接続または保存構造を確認できません。接続先の値や例外の詳細は表示しません。')
    elif not online: add('database','skipped','MySQL接続・保存構造','オフライン指定により接続確認を省略しました。')
    add('production','warning','本番受付・AP連携','本番受付は無効、AP連携は未接続です。実機・公開HTTPSの確認は別途必要です。')
    if config and any(config.get(k) is None for k in ('db_warning_bytes','backup_warning_bytes')):
        add('capacity','warning','容量警告','暫定案を作成し、承認した警告値を設定してください。')
    return dict(checks=checks,failed=sum(c['status']=='fail' for c in checks),online=online,local_start_checks_passed=not any(c['status']=='fail' for c in checks),production_ready=False,mutation_performed=False)

def require_startable(home):
    result=inspect_home(home,online=True,package_check=False)
    if result['failed']: raise ValueError('Preflight failed; run preflight for safe issue details')
