import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / '.deps'))

import concurrent.futures
import csv
import io
import json
import secrets
from database import DatabaseError
from mysql_fixture import new_database, PreservedDirectory, init_home, privileged
import tempfile
import time
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import generate_password_hash

from app import Service, create_app, uid, digest, timestamp
from jobs import housekeeping, monitor, notify, run_jobs, expire_backups
from workflow_backup import backup_stream as backup
from manage import initialize, add_admin, change_admin, mint_launch, unlock_login

ORIGIN = 'http://127.0.0.1:8890'


class Clock:
    def __init__(self):
        self.value = int(time.time())
    def __call__(self):
        return self.value


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = secrets.token_urlsafe(24)
        cls.password_hash = generate_password_hash(cls.password, method='scrypt')

    def setUp(self):
        self.temp = PreservedDirectory()
        self.home = Path(self.temp.name) / 'data'
        init_home(self.home, sample=True)
        self.clock = Clock()
        self.app = create_app(self.home, self.clock)
        self.s = self.app.extensions['service']
        self.client = self.app.test_client()
        self.csrf = None
        for role in ('settings', 'viewer', 'operator', 'records'):
            add_admin(self.s, role, role, self.password_hash)

    def tearDown(self):
        self.temp.cleanup()

    def get(self, path, client=None):
        return (client or self.client).get(path, base_url=ORIGIN)

    def post(self, path, body=None, key=None, client=None, csrf=None, headers=None):
        return (client or self.client).post(path, base_url=ORIGIN, json=body if body is not None else {},
                    headers={'Origin': ORIGIN, 'X-CSRF-Token': csrf if csrf is not None else self.csrf or '',
                             'Idempotency-Key': key or uid(), **(headers or {})})

    def visitor(self, client=None):
        r = self.post('/v1/session', client=client)
        token = r.json['csrf_token']
        if client is None:
            self.csrf = token
        return token

    def login(self, role='settings'):
        self.csrf = self.post('/v1/admin/session').json['csrf_token']
        r = self.post('/v1/admin/login', {'username': role, 'password': self.password})
        self.assertEqual(r.status_code, 200)
        self.csrf = r.json['csrf_token']
        return r

    def context(self):
        self.visitor()
        launch = mint_launch(self.s).split('=', 1)[1]
        r = self.post('/v1/contexts', {'launch_ref': launch})
        self.assertEqual(r.status_code, 201, r.json)
        return r.json['context_id']

    def consent_data(self):
        context = self.context()
        terms = self.get('/v1/contexts/' + context).json['terms']
        return {'context_id': context, 'accepted': True, 'terms_document_id': terms['document_id'],
                'terms_sha256': terms['sha256'], 'policy_version': terms['policy_version'], 'language': 'ja'}

    def consent(self):
        r = self.post('/v1/consents', self.consent_data())
        self.assertEqual(r.status_code, 201, r.json)
        return r.json

    def count(self, table):
        with self.s.db() as db:
            return db.execute('SELECT count(*) FROM ' + table).fetchone()[0]

    def test_preflight_warns_when_backup_policy_is_missing(self):
        from preflight import inspect_home
        codes=lambda home:{c['code']:c['status'] for c in inspect_home(home,online=False,package_check=False)['checks']}
        self.assertNotIn('backup_policy',codes(self.home))  # sample policy sets a retention period
        other=Path(self.temp.name)/'no-policy';init_home(other)
        self.assertEqual(codes(other)['backup_policy'],'warning')

    def test_default_init_is_stopped(self):
        other = Path(self.temp.name) / 'default'
        init_home(other)
        app = create_app(other)
        r = app.test_client().get('/v1/public', base_url=ORIGIN)
        self.assertEqual(r.json['service_state'], 'intake_disabled')

    def test_production_cannot_be_enabled(self):
        c = self.s.config.copy(); c['production_enabled'] = True
        (self.home / 'config.json').write_text(json.dumps(c), encoding='utf-8')
        with self.assertRaises(ValueError):
            Service(self.home)

    def test_pages_and_headers(self):
        for path in ('/', '/admin', '/health/live', '/health/ready'):
            r = self.get(path)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers['Cache-Control'], 'no-store')
            self.assertIn("frame-ancestors 'none'", r.headers['Content-Security-Policy'])
            self.assertEqual(r.headers['Referrer-Policy'], 'no-referrer')

    def test_origin_host_and_content_type(self):
        r = self.client.post('/v1/session', json={}, base_url=ORIGIN)
        self.assertEqual(r.status_code, 403)
        r = self.client.post('/v1/session', json={}, base_url=ORIGIN, headers={'Origin': 'https://evil.example'})
        self.assertEqual(r.status_code, 403)
        r = self.client.get('/health/live', base_url='http://evil.example:8890')
        self.assertEqual(r.status_code, 400)
        r = self.client.post('/v1/session', data='text', base_url=ORIGIN, headers={'Origin': ORIGIN})
        self.assertEqual(r.status_code, 415)

    def test_csrf_cookie_and_unauthenticated(self):
        r = self.post('/v1/admin/session')
        self.assertIn('HttpOnly', r.headers['Set-Cookie'])
        self.assertIn('SameSite=Strict', r.headers['Set-Cookie'])
        self.assertEqual(self.post('/v1/admin/login', {'username': 'settings', 'password': self.password}, csrf='invalid').status_code, 403)
        self.assertEqual(self.get('/v1/admin/overview').status_code, 401)

    def test_login_throttle_persists_restart(self):
        self.csrf = self.post('/v1/admin/session').json['csrf_token']
        for _ in range(5):
            self.assertEqual(self.post('/v1/admin/login', {'username': 'settings', 'password': 'wrong'}).status_code, 401)
        r = self.post('/v1/admin/login', {'username': 'settings', 'password': self.password})
        self.assertEqual(r.status_code, 429)
        self.assertEqual(r.headers['Retry-After'], '900')
        s2 = Service(self.home, self.clock)
        with s2.db() as db:
            self.assertEqual(db.execute('SELECT max(count) FROM login_limits').fetchone()[0], 5)
        self.clock.value += 901
        self.assertEqual(self.post('/v1/admin/login', {'username': 'settings', 'password': self.password}).status_code, 200)

    def test_login_lock_from_one_source_does_not_block_another(self):
        self.csrf = self.post('/v1/admin/session').json['csrf_token']
        for _ in range(5):
            self.assertEqual(self.post('/v1/admin/login', {'username': 'settings', 'password': 'wrong'}).status_code, 401)
        self.assertEqual(self.post('/v1/admin/login', {'username': 'settings', 'password': self.password}).status_code, 429)
        other = self.app.test_client()
        other.environ_base['REMOTE_ADDR'] = '127.0.0.2'
        csrf = self.post('/v1/admin/session', client=other).json['csrf_token']
        self.assertEqual(self.post('/v1/admin/login', {'username': 'settings', 'password': self.password},
                                   client=other, csrf=csrf).status_code, 200)

    def test_login_name_total_limit_spans_sources(self):
        for i in range(10):
            client = self.app.test_client()
            client.environ_base['REMOTE_ADDR'] = '127.0.1.' + str(i + 1)
            csrf = self.post('/v1/admin/session', client=client).json['csrf_token']
            for _ in range(5):
                self.assertEqual(self.post('/v1/admin/login', {'username': 'settings', 'password': 'wrong'},
                                           client=client, csrf=csrf).status_code, 401)
        self.csrf = self.post('/v1/admin/session').json['csrf_token']
        self.assertEqual(self.post('/v1/admin/login', {'username': 'settings', 'password': self.password}).status_code, 429)
        unlock_login(self.s, 'settings')
        self.assertEqual(self.post('/v1/admin/login', {'username': 'settings', 'password': self.password}).status_code, 200)
        with self.s.db() as db:
            self.assertTrue(db.execute("SELECT 1 FROM audit WHERE action='login_unlocked'").fetchone())

    def test_expired_sessions_are_reclaimed_and_admins_keep_reserved_capacity(self):
        self.visitor()
        self.clock.value += self.s.config['visitor_session_seconds'] + 1
        with patch('session_guard.MAX_RETAINED_SESSION_ROWS', 3), patch('session_guard.ADMIN_RESERVED_SESSION_ROWS', 1):
            self.visitor(self.app.test_client())
            self.assertEqual(self.count('sessions'), 1)
            self.visitor(self.app.test_client())
            r = self.post('/v1/session', client=self.app.test_client())
            self.assertEqual(r.status_code, 503)
            self.assertEqual(r.json['code'], 'session_capacity_exhausted')
            self.assertEqual(self.post('/v1/admin/session').status_code, 200)
        self.assertEqual(self.count('consents'), 0)

    def test_login_rotates_session_logout_invalidates(self):
        self.csrf = self.post('/v1/admin/session').json['csrf_token']
        before = self.client.get_cookie('admin_session', domain='127.0.0.1').value
        self.login()
        self.assertNotEqual(before, self.client.get_cookie('admin_session', domain='127.0.0.1').value)
        self.assertEqual(self.post('/v1/admin/logout').status_code, 200)
        self.assertEqual(self.get('/v1/admin/overview').status_code, 401)

    def test_absolute_session_expiry(self):
        self.login()
        self.clock.value += self.s.config['admin_session_seconds']
        self.assertEqual(self.get('/v1/admin/overview').status_code, 401)

    def test_account_disable_and_role_change_invalidate_sessions(self):
        self.login('operator')
        change_admin(self.s, 'operator', disable=True)
        self.assertEqual(self.get('/v1/admin/overview').status_code, 401)
        self.login('viewer')
        change_admin(self.s, 'viewer', role='operator')
        self.assertEqual(self.get('/v1/admin/overview').status_code, 401)

    def test_last_settings_administrator_cannot_be_disabled(self):
        for kwargs in ({'disable': True}, {'role': 'viewer'}):
            with self.assertRaises(ValueError):
                change_admin(self.s, 'settings', **kwargs)

    def test_role_viewer(self):
        self.login('viewer')
        for path, expected in [('/v1/admin/overview', 200), ('/v1/admin/notifications', 200),
                ('/v1/admin/grants', 403), ('/v1/admin/consents/export', 403), ('/v1/admin/settings', 403), ('/v1/admin/users', 403)]:
            self.assertEqual(self.get(path).status_code, expected, path)
        self.assertEqual(self.post('/v1/admin/grants/' + uid() + '/revocations', {'reason': 'abuse'}).status_code, 403)

    def test_role_operator(self):
        self.login('operator')
        self.assertEqual(self.get('/v1/admin/grants').status_code, 200)
        self.assertEqual(self.get('/v1/admin/consents/export').status_code, 403)
        self.assertEqual(self.get('/v1/admin/settings').status_code, 403)

    def test_role_records(self):
        self.login('records')
        self.assertEqual(self.get('/v1/admin/consents/export').status_code, 200)
        self.assertEqual(self.get('/v1/admin/grants').status_code, 403)
        self.assertEqual(self.get('/v1/admin/settings').status_code, 403)

    def test_role_settings(self):
        self.login()
        for path in ('/v1/admin/settings', '/v1/admin/users', '/v1/admin/grants', '/v1/admin/consents/export'):
            self.assertEqual(self.get(path).status_code, 200)
        self.assertNotIn('password', self.get('/v1/admin/users').get_data(as_text=True))

    def test_forged_launch_rejected(self):
        self.visitor()
        self.assertEqual(self.post('/v1/contexts', {'launch_ref': 'MAC=aa:bb:cc:dd:ee:ff'}).status_code, 403)

    def test_launch_bound_to_first_visitor(self):
        self.visitor()
        launch = mint_launch(self.s).split('=', 1)[1]
        r = self.post('/v1/contexts', {'launch_ref': launch})
        other = self.app.test_client(); csrf = self.visitor(other)
        r2 = self.post('/v1/contexts', {'launch_ref': launch}, client=other, csrf=csrf)
        self.assertEqual(r2.status_code, 403)
        self.assertEqual(self.get('/v1/contexts/' + r.json['context_id'], other).status_code, 404)

    def test_context_expires(self):
        context = self.context()
        self.clock.value += 300
        self.assertEqual(self.get('/v1/contexts/' + context).status_code, 404)

    def test_unsupported_language(self):
        self.assertEqual(self.get('/v1/public?lang=xx').status_code, 400)

    def test_consent_requires_explicit_acceptance(self):
        data = self.consent_data(); data['accepted'] = 1
        self.assertEqual(self.post('/v1/consents', data).status_code, 400)
        self.assertEqual(self.count('consents'), 0)

    def test_terms_hash_mismatch(self):
        data = self.consent_data(); data['terms_sha256'] = '0' * 64
        self.assertEqual(self.post('/v1/consents', data).status_code, 409)
        self.assertEqual(self.count('consents'), 0)

    def test_terms_immutable_document_id(self):
        (self.home / 'terms.ja.txt').write_text('Changed terms', encoding='utf-8')
        with self.assertRaises(ValueError):
            Service(self.home)

    def test_consent_immutable_in_database(self):
        self.consent()
        with self.assertRaises(DatabaseError):
            with self.s.db(True) as db:
                db.execute("UPDATE consents SET language='en'")

    def test_consent_transaction_atomic(self):
        data = self.consent_data()
        with patch.object(self.s, 'operation', side_effect=DatabaseError('TEST')):
            self.assertEqual(self.post('/v1/consents', data).status_code, 500)
        for table in ('consents', 'grants', 'operations'):
            self.assertEqual(self.count(table), 0)

    def test_idempotent_consent_and_body_conflict(self):
        data = self.consent_data(); key = uid()
        one = self.post('/v1/consents', data, key)
        two = self.post('/v1/consents', data, key)
        self.assertEqual(one.json, two.json)
        self.assertEqual(self.count('consents'), 1)
        data['accepted'] = True
        data['language'] = 'en'; data['terms_sha256'] = self.s.terms('en')['sha256']
        self.assertEqual(self.post('/v1/consents', data, key).status_code, 409)

    def test_concurrent_idempotency(self):
        data = self.consent_data(); key = uid()
        raw = self.client.get_cookie('portal_session', domain='127.0.0.1').value
        token = self.csrf
        def submit(_):
            client = self.app.test_client(); client.set_cookie('portal_session', raw, domain='127.0.0.1')
            return self.post('/v1/consents', data, key, client=client, csrf=token)
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results = list(pool.map(submit, range(2)))
        self.assertEqual([r.status_code for r in results], [201, 201])
        self.assertEqual(results[0].json, results[1].json)
        self.assertEqual(self.count('consents'), 1)

    def test_repeated_context_with_new_key_has_one_grant(self):
        data = self.consent_data()
        self.assertEqual(self.post('/v1/consents', data).status_code, 201)
        self.assertEqual(self.post('/v1/consents', data).status_code, 200)
        self.assertEqual(self.count('consents'), 1)

    def test_persistent_restart_and_no_sensitive_mapping(self):
        result = self.consent()
        app = create_app(self.home, self.clock)
        self.assertEqual(app.extensions['service'].adapter_name, 'disconnected')
        with app.extensions['service'].db() as db:
            row = dict(db.execute('SELECT * FROM consents').fetchone())
            self.assertEqual(row['id'], result['consent_id'])
            self.assertFalse({'ip', 'mac', 'email', 'name'} & set(row))
            self.assertEqual(row['delete_after'], timestamp(self.s.config['service_end_utc']) + 7 * 86400)

    def test_visitor_cannot_access_other_grant(self):
        grant = self.consent()['grant_id']
        other = self.app.test_client(); csrf = self.visitor(other)
        self.assertEqual(self.get('/v1/grants/' + grant, other).status_code, 404)
        self.assertEqual(self.post('/v1/grants/' + grant + '/handoffs', client=other, csrf=csrf).status_code, 404)

    def test_handoff_fails_closed(self):
        grant = self.consent()['grant_id']
        r = self.post('/v1/grants/' + grant + '/handoffs')
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.json['code'], 'adapter_unavailable')
        self.assertNotIn('secret', r.get_data(as_text=True))
        self.assertFalse(self.get('/v1/grants/' + grant).json['network_verified'])

    def test_db_accepted_is_not_connected_and_expiry_not_extended(self):
        grant = self.consent()['grant_id']
        deadline = self.clock.value + 60
        # AP-side acceptance is not written by the service account (no adapter yet); simulate it.
        with privileged(self.s.db_settings) as db:
            db.execute("UPDATE grants SET authorization_status='accepted',authorized_at=?,original_expires_at=?,observation_state='active',last_observed_at=? WHERE id=?",
                       (self.clock.value, deadline, self.clock.value, grant))
        r = self.get('/v1/grants/' + grant)
        self.assertNotEqual(r.json['display_state'], 'connected')
        self.clock.value += 61
        r = self.get('/v1/grants/' + grant)
        self.assertEqual(r.json['authorization_status'], 'expired')
        housekeeping(self.s)
        with self.s.db() as db:
            row = db.execute('SELECT * FROM grants WHERE id=?', (grant,)).fetchone()
            self.assertEqual(row['original_expires_at'], deadline)
            self.assertEqual(row['revocation_state'], 'failed')

    def test_revocation_atomic_idempotent_and_unconfirmed(self):
        grant = self.consent()['grant_id']; self.login('operator'); key = uid()
        path = '/v1/admin/grants/' + grant + '/revocations'
        one = self.post(path, {'reason': 'operator_request'}, key)
        two = self.post(path, {'reason': 'operator_request'}, key)
        self.assertEqual(one.status_code, 202)
        self.assertEqual(one.json, two.json)
        three = self.post(path, {'reason': 'operator_request'})
        self.assertEqual(one.json['operation_id'], three.json['operation_id'])
        housekeeping(self.s)
        op = self.get('/v1/admin/operations/' + one.json['operation_id']).json
        self.assertEqual(op['status'], 'failed')
        self.assertEqual(op['last_error_code'], 'adapter_unavailable')
        with self.s.db() as db:
            row = db.execute('SELECT * FROM grants WHERE id=?', (grant,)).fetchone()
            self.assertEqual(row['authorization_status'], 'revoked')
            self.assertNotEqual(row['revocation_state'], 'confirmed')

    def test_worker_persists_failure_without_repeated_send(self):
        self.consent()
        housekeeping(self.s); housekeeping(Service(self.home, self.clock))
        with self.s.db() as db:
            self.assertEqual(db.execute('SELECT attempts FROM operations').fetchone()[0], 1)

    def test_retention_is_preview_only_and_logs_are_preserved(self):
        self.consent()
        with self.s.db() as db:
            deadline = db.execute('SELECT delete_after FROM consents').fetchone()[0]
        self.clock.value = deadline
        result = housekeeping(self.s)
        self.assertEqual(result['consents'], 1)
        for table in ('consents', 'grants', 'operations', 'contexts', 'launches', 'sessions', 'idempotency'):
            self.assertGreater(self.count(table), 0, table)

    def test_export_is_audited_and_excludes_expired_records(self):
        self.consent(); self.login('records')
        r = self.get('/v1/admin/consents/export')
        self.assertEqual(r.status_code, 200)
        self.assertNotIn('connection_ref', r.get_data(as_text=True))
        with self.s.db() as db:
            self.assertTrue(db.execute("SELECT 1 FROM audit WHERE action='consents_export'").fetchone())
        self.assertEqual(self.get('/v1/admin/consents/export?after=-1').status_code, 400)

    def test_csv_formula_injection_escaped(self):
        # Deliberately create an unsafe version before the consent insert; DB records remain immutable.
        self.s.config['terms_version'] = '=1+1'
        self.consent(); self.login('records')
        r = self.get('/v1/admin/consents/export')
        rows = list(csv.reader(io.StringIO(r.get_data(as_text=True).lstrip('\ufeff'))))
        self.assertEqual(rows[1][2], "'=1+1")





    def test_expired_backups_are_kept_by_operator_instruction(self):
        path = backup(self.s)
        self.clock.value += 7 * 86400
        self.assertEqual(expire_backups(self.s), 0)
        self.assertTrue(path.exists())

    def test_notifications_dedupe_ack_resolve_reopen(self):
        monitor(self.s); monitor(self.s)
        with self.s.db() as db:
            row = db.execute("SELECT * FROM notifications WHERE code='adapter_unavailable'").fetchone()
            self.assertEqual(db.execute("SELECT count(*) FROM notifications WHERE code='adapter_unavailable'").fetchone()[0], 1)
        self.login('operator')
        self.assertEqual(self.post('/v1/admin/notifications/' + row['id'] + '/acknowledgements',
                                   headers={'X-Expected-Generation':str(row['generation'])}).status_code, 200)
        monitor(self.s)
        with self.s.db(True) as db:
            self.assertEqual(db.execute('SELECT state FROM notifications WHERE id=?', (row['id'],)).fetchone()[0], 'acknowledged')
            notify(db, self.s.now(), 'adapter_unavailable', '', False)
            notify(db, self.s.now(), 'adapter_unavailable', 'Again')
        with self.s.db() as db:
            self.assertEqual(db.execute('SELECT state FROM notifications WHERE id=?', (row['id'],)).fetchone()[0], 'open')

    def test_backup_failure_creates_notification_and_recovery_resolves(self):
        with patch('workflow_backup.backup_stream', side_effect=OSError('TEST')):
            self.assertTrue(run_jobs(self.s)['backup_failed'])
        with self.s.db() as db:
            self.assertEqual(db.execute("SELECT state FROM notifications WHERE code='backup_failed'").fetchone()[0], 'open')
        self.assertFalse(run_jobs(self.s)['backup_failed'])
        with self.s.db() as db:
            self.assertEqual(db.execute("SELECT state FROM notifications WHERE code='backup_failed'").fetchone()[0], 'resolved')

    def test_monitor_detects_low_disk_and_job_staleness(self):
        self.assertEqual(self.get('/health/jobs').status_code, 503)
        with patch('operations.shutil.disk_usage') as disk:
            disk.return_value.free = 0
            run_jobs(self.s, with_backup=False)
        self.assertEqual(self.get('/health/jobs').status_code, 200)
        with self.s.db() as db:
            self.assertEqual(db.execute("SELECT severity FROM notifications WHERE code='disk_low'").fetchone()[0], 'critical')
        self.clock.value += 120
        self.assertEqual(self.get('/health/jobs').status_code, 503)

    def test_large_body_and_error_do_not_echo_secrets(self):
        marker = 'test-private-' + secrets.token_hex(8)
        r = self.post('/v1/contexts', {'launch_ref': marker + 'x' * 17000})
        self.assertIn(r.status_code, (401, 413))
        self.assertNotIn(marker, r.get_data(as_text=True))

    def test_invalid_schema_and_version_fail_closed(self):
        with self.s.db(True) as db:
            db.execute("UPDATE meta SET value='999' WHERE name='schema_version'")
        with self.assertRaises(ValueError):
            Service(self.home)

    def test_backup_without_retention_does_not_create_unbounded_archive(self):
        self.s.config['backup_retention_days'] = None
        with self.assertRaises(ValueError):
            backup(self.s)
        self.assertFalse((self.home / 'backups').exists())

    def test_changed_language_cannot_be_misreported_as_existing_consent(self):
        data = self.consent_data()
        self.assertEqual(self.post('/v1/consents', data).status_code, 201)
        data.update(language='en', terms_sha256=self.s.terms('en')['sha256'])
        r = self.post('/v1/consents', data)
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json['code'], 'context_already_consented')
        self.assertEqual(self.count('consents'), 1)

    def test_unknown_fields_and_invalid_json_rejected(self):
        self.visitor()
        self.assertEqual(self.post('/v1/contexts', {'launch_ref': 'unverified', 'mac': 'untrusted'}).status_code, 400)
        r = self.client.post('/v1/contexts', base_url=ORIGIN, data='{', content_type='application/json',
                headers={'Origin': ORIGIN, 'X-CSRF-Token': self.csrf})
        self.assertEqual(r.status_code, 400)

    def test_revocation_rolls_back_if_outbox_cannot_be_written(self):
        grant = self.consent()['grant_id']; self.login('operator')
        with patch.object(self.s, 'operation', side_effect=DatabaseError('TEST')):
            r = self.post('/v1/admin/grants/' + grant + '/revocations', {'reason': 'operator_request'})
            self.assertEqual(r.status_code, 500)
        with self.s.db() as db:
            self.assertEqual(db.execute('SELECT authorization_status FROM grants WHERE id=?', (grant,)).fetchone()[0], 'pending')

    def test_old_authorization_observation_is_marked_stale(self):
        grant = self.consent()['grant_id']
        with privileged(self.s.db_settings) as db:
            db.execute("UPDATE grants SET observation_state='active',last_observed_at=? WHERE id=?", (self.clock.value - 30, grant))
        r = self.get('/v1/grants/' + grant).json
        self.assertEqual(r['observation_state'], 'stale')
        self.assertFalse(r['network_verified'])

    def test_nonempty_mysql_database_cannot_activate_partial_initialization(self):
        self.consent()
        other=Path(self.temp.name)/'invalid-reuse'
        with self.assertRaisesRegex(ValueError,'not empty'):
            init_home(other,settings=self.s.db_settings)
        # The read-only precheck refuses before any data folder exists.
        self.assertFalse(other.exists())
        self.assertEqual(self.count('consents'),1)

    def test_operator_deletion_stop_cannot_be_enabled_in_configuration(self):
        c=self.s.config.copy();c['automatic_deletion_enabled']=True
        (self.home/'config.json').write_text(json.dumps(c),encoding='utf-8')
        with self.assertRaises(ValueError):
            Service(self.home)


if __name__ == '__main__':
    unittest.main(verbosity=2)
