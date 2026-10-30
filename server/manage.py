"""Operator CLI. Passwords are read interactively, never from command arguments."""
import sys
from pathlib import Path

# Optional checkout-local dependencies. Normal venv installation needs no special path.
deps = Path(__file__).resolve().parent / '.deps'
if deps.is_dir():
    sys.path.insert(0, str(deps))

import argparse
import getpass
import json
import os
import re
import shutil
import time

from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import ROOT, ROLES, Service, create_app, digest, uid, utc
from jobs import backup, housekeeping, restore, run_jobs, secure_new_file
from security import protect_directory
from database import load_settings, initialize_schema, connect


def _initialize_v4_history(home, sample=False, restored=False, db_settings=None):
    home = Path(home).resolve()
    if not restored:
        home.mkdir(mode=0o700, parents=True, exist_ok=False)
    if restored and (not (home / 'mysql.json').exists() or (home / 'config.json').exists() or (home/'restore.incomplete').exists()):
        raise ValueError('Not an unprepared restored directory')
    protect_directory(home)
    if not restored and not db_settings:
        raise ValueError('MySQL settings are required')
    if not restored:
        secure_new_file(home/'initialization.incomplete',b'initialization pending')
    c = json.loads((ROOT / 'config.example.json').read_text(encoding='utf-8'))
    if sample:
        c.update(local_intake_enabled=True, event_id=uid(), service_window_id=uid(), terms_document_id=uid(),
                 terms_version='local-draft-1', policy_version='local-test-1',
                 service_start_utc=utc(int(time.time()) - 60), service_end_utc=utc(int(time.time()) + 86400),
                 retention_days=7, audit_retention_days=7, backup_retention_days=7)
    secure_new_file(home / 'config.json', (json.dumps(c, ensure_ascii=False, indent=2) + '\n').encode())
    secure_new_file(home / 'session.key', os.urandom(32))
    secure_new_file(home / 'backup.key', Fernet.generate_key())
    secure_new_file(home / 'mfa.key', Fernet.generate_key())
    for lang in ('ja', 'en'):
        shutil.copyfile(ROOT / f'terms.{lang}.txt', home / f'terms.{lang}.txt')
    if not restored:
        secure_new_file(home/'mysql.json',json.dumps(db_settings).encode())
        initialize_schema(db_settings,ROOT/'schema.sql')
        (home/'initialization.incomplete').unlink()
    s = Service(home)
    if restored:
        housekeeping(s)
    return s


from workflow_cli import initialize


def read_password():
    one = getpass.getpass('New password (14+ characters): ')
    if len(one) < 14 or len(one) > 256:
        raise ValueError('Password must be 14..256 characters')
    if one != getpass.getpass('Confirm password: '):
        raise ValueError('Passwords do not match')
    return generate_password_hash(one, method='scrypt')


def add_admin(s, username, role, password_hash):
    username = username.strip().lower()
    if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{2,79}', username) or role not in ROLES:
        raise ValueError('Invalid username or role')
    with s.db(True) as db:
        administrator_id=uid()
        db.execute('INSERT INTO admins VALUES (?,?,?,?,1)', (administrator_id, username, password_hash, role))
        s.audit(db, 'local_cli', 'admin_created',administrator_id)


def change_admin(s, username, role=None, disable=False, password_hash=None):
    with s.db(True) as db:
        a = db.execute('SELECT * FROM admins WHERE username=?', (username.strip().lower(),)).fetchone()
        if not a:
            raise ValueError('Unknown administrator')
        if a['enabled'] and a['role'] == 'settings' and (disable or (role and role != 'settings')):
            count = db.execute("SELECT count(*) FROM admins WHERE enabled=1 AND role='settings'").fetchone()[0]
            if count <= 1:
                raise ValueError('Cannot disable/demote the last settings administrator')
        if role:
            db.execute('UPDATE admins SET role=? WHERE id=?', (role, a['id']))
        if disable:
            db.execute('UPDATE admins SET enabled=0 WHERE id=?', (a['id'],))
        if password_hash:
            db.execute('UPDATE admins SET password_hash=?,enabled=1 WHERE id=?', (password_hash, a['id']))
        db.execute("DELETE FROM sessions WHERE kind LIKE 'admin%' AND owner_id=?", (a['id'],))
        s.audit(db, 'local_cli', 'admin_changed', a['id'])


def mint_launch(s):
    s.intake()
    raw = __import__('secrets').token_urlsafe(32)
    with s.db(True) as db:
        db.execute('INSERT INTO launches VALUES (?,?,?,NULL,NULL)', (digest(raw), 'local:' + uid(), s.now() + 300))
        s.audit(db, 'local_cli', 'local_launch_created')
    # Fragment is removed by the page before network calls, never sent in a URL to the server.
    return s.config['origin'] + '/#local_launch=' + raw


def main():
    p = argparse.ArgumentParser(description='Festival Wi-Fi LOCAL service; production networking is not implemented.')
    p.add_argument('--home', required=True, type=Path, help='Protected persistent data directory')
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('configure-mysql',help='Write protected MySQL settings with an interactively entered password')
    init = sub.add_parser('init')
    init.add_argument('--sample-policy', action='store_true', help='Explicitly enable LOCAL 1-day intake, provisional terms and 7-day retention')
    init.add_argument('--db-config',type=Path,required=True,help='Protected MySQL connection JSON; never put passwords in command arguments')
    init.add_argument('--maintenance-db-config',type=Path,required=True)
    from workflow_cli import register as register_workflow_cli
    register_workflow_cli(sub)
    sub.add_parser('prepare-restored')
    add = sub.add_parser('add-admin')
    add.add_argument('username')
    add.add_argument('--role', choices=sorted(ROLES), required=True)
    edit = sub.add_parser('change-admin')
    edit.add_argument('username')
    edit.add_argument('--role', choices=sorted(ROLES))
    edit.add_argument('--disable', action='store_true')
    edit.add_argument('--password', action='store_true', help='Read a replacement password interactively')
    sub.add_parser('serve')
    sub.add_parser('run-jobs')
    sub.add_parser('worker')
    sub.add_parser('backup')
    sub.add_parser('backup-stream',help='Create a bounded-memory streaming MySQL backup')
    preflight=sub.add_parser('preflight',help='Collect configuration, key, permission, package and MySQL checks')
    preflight.add_argument('--offline',action='store_true')
    kit=sub.add_parser('create-recovery-kit',help='Stopped service only; encrypted DB/files with a separate NEW key directory')
    kit.add_argument('--output',type=Path,required=True)
    kit.add_argument('--key-directory',type=Path,required=True)
    kit_restore=sub.add_parser('restore-recovery-kit',help='Restore to NEW home and EMPTY DB, preserve extracted evidence separately')
    kit_restore.add_argument('--source',type=Path,required=True)
    kit_restore.add_argument('--key-file',type=Path,required=True)
    kit_restore.add_argument('--db-config',type=Path,required=True)
    sub.add_parser('mint-local-link')
    sub.add_parser('status')
    capacity=sub.add_parser('plan-capacity',help='Read current usage and write a provisional warning plan; no deletion')
    capacity.add_argument('--output',type=Path,required=True)
    capacity_apply=sub.add_parser('apply-capacity',help='Apply a reviewed capacity plan while the owned service is stopped')
    capacity_apply.add_argument('--plan',type=Path,required=True)
    information_apply=sub.add_parser('apply-event-information',help='Apply a reviewed display-information plan while app and worker are stopped')
    information_apply.add_argument('--plan',type=Path,required=True)
    sub.add_parser('ap-check',help='Inspect AP inventory without connecting to or modifying an AP')
    sub.add_parser('diagnose-mysql',help='Inspect MySQL connection and grants; never changes permissions')
    sub.add_parser('upgrade-from-2',help='Explicit additive schema upgrade; stop the app and back up with the old release first')
    sub.add_parser('upgrade-data',help='Explicit additive schema upgrade from 2 or 3 to 4; stop and back up first')
    https=sub.add_parser('prepare-https',help='Offline HTTPS plan; creates a closed configuration, never enables forwarding')
    https.add_argument('--plan',type=Path,required=True)
    https.add_argument('--output',type=Path,required=True)
    verify=sub.add_parser('verify-backup',help='Authenticate and inspect a backup; record the actual result')
    verify.add_argument('filename')
    verify.add_argument('--key-file',type=Path)
    restore_verify=sub.add_parser('verify-restore',help='Restore a backup to a NEW folder and EMPTY separate DB; compare retained records')
    restore_verify.add_argument('filename')
    restore_verify.add_argument('--destination',type=Path,required=True)
    restore_verify.add_argument('--db-config',type=Path,required=True)
    restore_verify.add_argument('--key-file',type=Path)
    mfa_add=sub.add_parser('enroll-mfa',help='Interactive terminal-only authenticator enrollment')
    mfa_add.add_argument('username')
    mfa_reset=sub.add_parser('reset-mfa',help='Local terminal recovery; audited and invalidates sessions')
    mfa_reset.add_argument('username')
    rest = sub.add_parser('restore-to-new')
    rest.add_argument('--source', type=Path, required=True)
    rest.add_argument('--key-file', type=Path, required=True)
    rest.add_argument('--db-config',type=Path,required=True,help='Connection file for an EMPTY separate MySQL database')
    args = p.parse_args()
    from workflow_cli import handle as handle_workflow_cli
    if handle_workflow_cli(args): return
    if args.command in ('apply-event-information','restore-to-new','restore-recovery-kit','prepare-restored','upgrade-from-2','upgrade-data','verify-restore'):
        raise ValueError('Use explicit schema-five commands, or the matching preserved legacy release')
    if args.command=='preflight':
        from preflight import inspect_home
        result=inspect_home(args.home,online=not args.offline)
        print(json.dumps(result,ensure_ascii=False,indent=2));raise SystemExit(2 if result['failed'] else 0)
    if args.command=='restore-recovery-kit':
        from recovery_kit import restore_kit
        print(json.dumps(restore_kit(args.source,args.key_file,args.home,load_settings(args.db_config)),ensure_ascii=False,indent=2));return
    if args.command=='prepare-https':
        from deployment_plan import write_plan
        print(json.dumps(write_plan(args.plan,args.output),ensure_ascii=False,indent=2));return
    if args.command == 'configure-mysql':
        c=dict(host=input('MySQL host [127.0.0.1]: ').strip() or '127.0.0.1',
               port=int(input('MySQL port [3306]: ').strip() or '3306'),
               database=input('Dedicated EMPTY database name: ').strip(),
               user=input('MySQL application user: ').strip(),password=getpass.getpass('MySQL password: '))
        if c['host'] not in ('127.0.0.1','localhost'):
            c['ssl_ca']=input('Trusted CA file (absolute path): ').strip()
        args.home.mkdir(mode=0o700,parents=True,exist_ok=False);protect_directory(args.home)
        secure_new_file(args.home/'mysql.json',json.dumps(c).encode())
        raw=connect(load_settings(args.home/'mysql.json'));raw.close()
        print('MySQL settings saved in protected directory; connection succeeded. Password not printed.')
        return
    if args.command == 'init':
        initialize(args.home, args.sample_policy,db_settings=load_settings(args.db_config),maintenance_file=args.maintenance_db_config,open_service=False)
        print('Initialized LOCAL service. Production is disabled. No administrator exists yet.')
        print('Next: apply the service-account grants (tools/mysql_grants.py runtime), then run preflight and add-admin.')
        return
    if args.command == 'restore-to-new':
        restore(args.source, args.key_file, args.home,load_settings(args.db_config))
        print('Restored to NEW directory; prepare-restored is required. Intake remains disabled.')
        return
    if args.command == 'prepare-restored':
        initialize(args.home, restored=True)
        print('Prepared with NEW session/backup keys. Old sessions removed; grants are not reauthorized. Intake disabled.')
        return
    if args.command == 'ap-check':
        from ap_profile import inspect_profile
        print(json.dumps(inspect_profile(args.home/'device-profile.json'),ensure_ascii=False,indent=2));return
    if args.command == 'diagnose-mysql':
        from operations import mysql_diagnostic
        print(json.dumps(mysql_diagnostic(load_settings(args.home/'mysql.json')),ensure_ascii=False,indent=2));return
    if args.command in ('upgrade-from-2','upgrade-data'):
        from migrations import upgrade_to_v4
        upgraded=upgrade_to_v4(load_settings(args.home/'mysql.json'),args.home)
        if not (args.home/'mfa.key').exists(): secure_new_file(args.home/'mfa.key',Fernet.generate_key())
        print('Schema 4 ready; records retained. Restart with this release. Changed='+str(upgraded));return
    if args.command in ('serve','worker'):
        from preflight import require_startable
        require_startable(args.home)
    if args.command=='serve':
        application=create_app(args.home);s=application.extensions['service']
    else:s=Service(args.home)
    if args.command=='apply-event-information':
        from event_information import apply_plan
        print(json.dumps(apply_plan(s,json.loads(args.plan.read_text(encoding='utf-8')))));return
    if args.command=='plan-capacity':
        from capacity_policy import make_plan
        secure_new_file(args.output,json.dumps(make_plan(s),ensure_ascii=False,indent=2).encode())
        print('Provisional capacity plan saved. Review it before apply-capacity; nothing deleted.')
    elif args.command=='apply-capacity':
        from capacity_policy import apply_plan
        apply_plan(s,json.loads(args.plan.read_text(encoding='utf-8-sig')))
        print('Capacity warnings configured. Previous configuration and audit retained; restart the service.')
    elif args.command == 'add-admin':
        add_admin(s, args.username, args.role, read_password())
        print('Administrator created. No password is printed or logged.')
    elif args.command == 'change-admin':
        change_admin(s, args.username, args.role, args.disable, read_password() if args.password else None)
        print('Administrator updated; existing administrator sessions invalidated.')
    elif args.command=='enroll-mfa':
        if not sys.stdin.isatty() or not sys.stdout.isatty(): raise ValueError('Use an interactive private terminal')
        import base64,secrets
        from mfa import enroll
        secret=base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')
        print('Enter this secret into your authenticator (SHA1, 6 digits, 30 seconds). Do not record the terminal.')
        print(secret)
        codes=enroll(s,args.username.strip().lower(),secret,getpass.getpass('Authenticator code: ').strip())
        print('Single-use recovery codes. Store privately outside this computer:')
        for code in codes: print(code)
        print('Enrollment complete. Existing sessions invalidated. Codes are not logged.')
    elif args.command=='reset-mfa':
        if not sys.stdin.isatty() or not sys.stdout.isatty(): raise ValueError('Use an interactive private terminal')
        if input('Type RESET '+args.username+' to reset additional authentication: ')!='RESET '+args.username: raise ValueError('Cancelled')
        from mfa import reset
        reset(s,args.username.strip().lower())
        print('Additional authentication reset and audited. Re-enroll before normal operation.')
    elif args.command=='verify-backup':
        from backup_review import decrypt_check
        result=decrypt_check(s,args.filename,key_file=args.key_file)
        print(json.dumps(result,ensure_ascii=False))
        if result['status']!='passed': raise SystemExit(2)
    elif args.command=='verify-restore':
        from backup_review import restore_check
        result=restore_check(s,args.filename,args.destination,load_settings(args.db_config),args.key_file)
        print(json.dumps(result,ensure_ascii=False))
        if result['status']!='passed': raise SystemExit(2)
    elif args.command == 'mint-local-link':
        print('LOCAL ONLY — one browser, expires in 300 seconds; no network permission:')
        print(mint_launch(s))
    elif args.command == 'serve':
        from urllib.parse import urlsplit
        from waitress import serve
        from runtime_guard import owned_runtime
        from workflow_generation import runtime_heartbeat
        s=application.extensions['service']
        print('LOCAL server: ' + s.config['origin'] + ' (Ctrl+C to stop)', flush=True)
        with owned_runtime(s.home,'app'),runtime_heartbeat(application.extensions['service'],'app'):
            serve(application, host='127.0.0.1', port=urlsplit(s.config['origin']).port,
                  threads=4, max_request_body_size=65536, clear_untrusted_proxy_headers=not s.transport['enabled'])
    elif args.command == 'backup':
        print(str(backup(s)))
    elif args.command=='backup-stream':
        from stream_backup import backup_stream
        print(str(backup_stream(s)))
    elif args.command=='create-recovery-kit':
        from recovery_kit import create_kit
        print(json.dumps(create_kit(s,args.output,args.key_directory),ensure_ascii=False,indent=2))
    elif args.command == 'run-jobs':
        from runtime_guard import owned_runtime
        from workflow_generation import runtime_heartbeat
        with owned_runtime(s.home,'worker'),runtime_heartbeat(s,'worker'):
            result = run_jobs(s)
        print(json.dumps(result))
        if result['backup_failed']:
            raise SystemExit(2)
    elif args.command == 'worker':
        print('LOCAL worker started (30 seconds). Ctrl+C to stop.', flush=True)
        from runtime_guard import owned_runtime
        from workflow_generation import runtime_heartbeat
        with owned_runtime(s.home,'worker'),runtime_heartbeat(s,'worker'):
            while True:
                try:
                    result = run_jobs(s)
                    print(json.dumps({'at': utc(s.now()), **result}), flush=True)
                except Exception as e:
                    print('worker_failed type=' + type(e).__name__, file=sys.stderr, flush=True)
                time.sleep(30)
    elif args.command == 'status':
        with s.db() as db:
            print(json.dumps({'mode': 'local', 'production_enabled': False, 'adapter': 'disconnected',
                              'schema_version': db.execute("SELECT value FROM meta WHERE name='schema_version'").fetchone()[0],
                              'consents': db.execute('SELECT count(*) FROM consents').fetchone()[0],
                              'enabled_admins': db.execute('SELECT count(*) FROM admins WHERE enabled=1').fetchone()[0]}))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        # CLI diagnostics deliberately omit SQL rows, request bodies, and secret values.
        print('Command failed: ' + type(e).__name__ + '. Check the operation guide and data directory.', file=sys.stderr)
        raise SystemExit(1)
