"""Local-only consent service. No NAS/RADIUS adapter is installed in this release."""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import ipaddress
import json
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

from database import DatabaseError, transaction, load_settings
from worker_status import worker_status
from session_guard import SessionIssueGuard, GuardRejected, require_storage_capacity

PUBLIC_TERMS_SECONDS = 5

from flask import Flask, g, jsonify, render_template, request, make_response
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent
ROLES = {'viewer', 'operator', 'records', 'settings'}
PERMISSIONS = {
    'read': ROLES,
    'operate': {'operator', 'settings'},
    'records': {'records', 'settings'},
    'settings': {'settings'},
}


def uid():
    return str(uuid.uuid4())


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace('+00:00', 'Z')


def timestamp(value):
    if not isinstance(value, str) or not value.endswith('Z'):
        raise ValueError('UTC timestamp must end in Z')
    return int(datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp())


class ApiError(Exception):
    def __init__(self, code, status=400, message=None, *, retry_after=None):
        self.code, self.status = code, status
        self.message = message or code
        self.retry_after = retry_after


class Service:
    adapter_name = 'disconnected'

    def __init__(self, home, clock=time.time):
        self.home = Path(home).resolve()
        if any((self.home/name).exists() or __import__('filesystem_guard').is_link(self.home/name) for name in ('initialization.incomplete','restore.incomplete','upgrade.incomplete','policy-apply.incomplete')):
            raise ValueError('Incomplete initialization or restore; do not start')
        config_bytes = (self.home / 'config.json').read_bytes()
        self.config = json.loads(config_bytes)
        self.loaded_config_sha256 = hashlib.sha256(config_bytes).hexdigest()
        self.instance_id = uid()
        self.key = (self.home / 'session.key').read_bytes()
        if len(self.key) != 32:
            raise ValueError('Invalid session key')
        self.session_guard = SessionIssueGuard()
        self.public_terms_lock = threading.Lock(); self.public_terms_cache = {}; self.public_terms_generation = 0
        self.db_settings = load_settings(self.home / 'mysql.json')
        self.clock = clock
        self.term_text = {lang: (self.home / f'terms.{lang}.txt').read_text(encoding='utf-8') for lang in ('ja', 'en')}
        self.validate_config()
        from network_access import NetworkAccess
        self.network = NetworkAccess(self, self.network_settings) if self.network_settings else None
        self.adapter_name = 'vyos' if self.network else 'disconnected'
        with self.db() as db:
            version = db.execute("SELECT value FROM meta WHERE name='schema_version'").fetchone()
            if version is None or version[0] != '5':
                raise ValueError('Unsupported database version; do not start')
            from workflow_database import verify_contract
            verify_contract(db)
        from workflow_generation import require_runtime_ready
        require_runtime_ready(self)
        if self.config.get('local_intake_enabled'):
            with self.db(True) as db:
                for lang in ('ja', 'en'):
                    t = self.terms(lang,db)
                    old = db.execute('SELECT * FROM terms_documents WHERE document_id=? AND language=?', (t['document_id'], lang)).fetchone()
                    if old and (old['version'], old['sha256']) != (t['version'], t['sha256']):
                        raise ValueError('Terms changed without a new document ID')
                    if not old: db.execute('INSERT INTO terms_documents VALUES (?,?,?,?,?)',
                               (t['document_id'], lang, t['version'], t['sha256'], t['text']))

    def validate_config(self):
        c = self.config
        from event_information import current
        current(c)
        # This release intentionally has no production-enable escape hatch.
        if c.get('mode') != 'local' or c.get('production_enabled') is not False:
            raise ValueError('Production mode is not supported by this release')
        if c.get('automatic_deletion_enabled') is not False:
            raise ValueError('Automatic deletion is disabled by the operator instruction')
        from transport import validate_transport
        self.transport=validate_transport(c)
        from network_access import validate as validate_network
        self.network_settings=validate_network(c,self.home)
        if c.get('backup_format') != 'stream-v2':
            raise ValueError('Unsupported backup format')
        workflow=c.get('workflow_policy')
        if workflow is not None:
            if not isinstance(workflow,dict) or type(workflow.get('approved')) is not bool:raise ValueError('Invalid workflow approval flag')
            if workflow['approved']:
                from workflow_common import policy
                try:policy(self)
                except ApiError as error:raise ValueError('Invalid approved workflow policy') from error
        origin = urlsplit(c['origin'])
        if (origin.scheme != 'http' or origin.hostname != '127.0.0.1'
                or not origin.port or origin.path or origin.query or origin.fragment or origin.username):
            raise ValueError('Local origin must be http://127.0.0.1:PORT')
        for k in ('retention_days', 'backup_retention_days', 'audit_retention_days'):
            v = c.get(k)
            if v is not None and (type(v) is not int or not 1 <= v <= 3650):
                raise ValueError(f'Invalid {k}')
        for k in ('admin_session_seconds', 'visitor_session_seconds', 'backup_interval_seconds', 'min_free_bytes'):
            if type(c.get(k)) is not int or c[k] <= 0:
                raise ValueError(f'Invalid {k}')
        if type(c.get('server_threads', 8)) is not int or not 1 <= c.get('server_threads', 8) <= 64:
            raise ValueError('Invalid server_threads')
        for k in ('db_warning_bytes','backup_warning_bytes'):
            value=c.get(k)
            if value is not None and (type(value) is not int or not 1<=value<=2**63-1):
                raise ValueError(f'Invalid {k}')
        if c.get('local_intake_enabled'):
            for k in ('event_id', 'service_window_id', 'terms_document_id'):
                uuid.UUID(c[k])
            for k in ('policy_version', 'terms_version', 'retention_days', 'audit_retention_days', 'backup_retention_days'):
                if not c.get(k):
                    raise ValueError(f'Missing {k}')
            if timestamp(c['service_end_utc']) <= timestamp(c['service_start_utc']):
                raise ValueError('Invalid service window')
        from daily_hours import validate as validate_daily_hours
        validate_daily_hours(c.get('daily_service_hours'))
        for lang in ('ja', 'en'):
            if not (self.home / f'terms.{lang}.txt').read_text(encoding='utf-8').strip():
                raise ValueError('Empty terms')

    def now(self):
        return int(self.clock())

    def db(self, write=False):
        return transaction(self.db_settings, write)

    def terms(self, lang, db=None):
        from operator_features import active_terms
        if db is None:
            with self.db() as current:
                published=active_terms(self,lang,current)
        else: published=active_terms(self,lang,db)
        if published: return published
        text = self.term_text[lang]
        return dict(document_id=self.config['terms_document_id'], version=self.config['terms_version'],
                    policy_version=self.config['policy_version'], language=lang, text=text, sha256=digest(text))

    def public_terms(self, lang):
        # Every visitor's landing page reads the same published terms; a short shared copy spares one DB round trip each.
        now = time.monotonic()
        with self.public_terms_lock:
            cached, generation = self.public_terms_cache.get(lang), self.public_terms_generation
        if cached and now - cached[0] < PUBLIC_TERMS_SECONDS:
            return cached[1]
        terms = self.terms(lang)
        with self.public_terms_lock:
            # A publication during the read bumps the generation, so the older copy is not kept.
            if generation == self.public_terms_generation:
                self.public_terms_cache[lang] = (now, terms)
        return terms

    def forget_public_terms(self):
        with self.public_terms_lock:
            self.public_terms_generation += 1; self.public_terms_cache.clear()

    def intake(self):
        if not self.config.get('local_intake_enabled'):
            raise ApiError('intake_disabled', 503, '受付は停止中です。運営者の設定を待っています。')
        if not timestamp(self.config['service_start_utc']) <= self.now() < timestamp(self.config['service_end_utc']):
            raise ApiError('service_closed', 410, '提供期間外です。')
        from daily_hours import is_open
        if not is_open(self.config.get('daily_service_hours'), self.now()):
            raise ApiError('service_closed', 410, '本日の提供時間外です。')

    def record_deadline(self):
        return timestamp(self.config['service_end_utc']) + self.config['retention_days'] * 86400

    def audit(self, db, actor, action, object_id=None):
        days = self.config.get('audit_retention_days')
        if days is None:
            # Preconfiguration actions have a documented local technical TTL of 24 hours.
            days = 1
        db.execute('INSERT INTO audit VALUES (?,?,?,?,?,?)',
                   (uid(), actor, action, object_id, self.now(), self.now() + days * 86400))

    def pseudonym(self, value):
        return hmac.new(self.key, value.encode(), hashlib.sha256).hexdigest()

    def csrf(self, raw):
        return self.pseudonym('csrf:' + raw)

    def new_session(self, db, kind, owner):
        require_storage_capacity(db)
        raw = secrets.token_urlsafe(32)
        ttl = self.config['admin_session_seconds' if kind.startswith('admin') else 'visitor_session_seconds']
        db.execute('INSERT INTO sessions VALUES (?,?,?,?,?,?)',
                   (digest(raw), kind, owner, digest(self.csrf(raw)), self.now() + ttl, self.now()))
        return raw

    def get_session(self, kind):
        name = 'admin_session' if kind == 'admin' else 'portal_session'
        raw = request.cookies.get(name, '')
        if not raw or len(raw) > 128:
            return None
        with self.db() as db:
            s = db.execute('SELECT * FROM sessions WHERE token_hash=? AND expires_at>?',
                           (digest(raw), self.now())).fetchone()
            if s is None or not (s['kind'].startswith('admin') if kind == 'admin' else s['kind'] == 'visitor'):
                return None
            result = dict(s)
            if s['kind'] in ('admin','admin_mfa'):
                a = db.execute('SELECT id,username,role,enabled FROM admins WHERE id=?', (s['owner_id'],)).fetchone()
                if not a or not a['enabled']:
                    return None
                result['admin'] = dict(a)
        result['raw'] = raw
        return result

    def check_csrf(self, s):
        if not s or not hmac.compare_digest(s['csrf_hash'], digest(request.headers.get('X-CSRF-Token', ''))):
            raise ApiError('csrf_invalid', 403, '画面を開き直して、もう一度操作してください。')

    def require_admin_transaction(self,db,session,permission='read'):
        current=db.execute("SELECT a.role FROM sessions t JOIN admins a ON a.id=t.owner_id WHERE t.token_hash=? AND t.kind='admin' AND t.owner_id=? AND t.expires_at>? AND a.enabled=1",
                           (session['token_hash'],session['owner_id'],self.now())).fetchone()
        if not current:raise ApiError('authentication_required',401,'ログインが必要です。')
        if current['role'] not in PERMISSIONS[permission or 'read']:raise ApiError('permission_denied',403,'この操作の権限がありません。')

    def idempotent(self, db, owner, action, *, fingerprint=None):
        session=g.get('session')
        if session and session['kind']=='admin':self.require_admin_transaction(db,session,g.get('required_permission'))
        key = request.headers.get('Idempotency-Key', '')
        try:
            uuid.UUID(key)
        except ValueError:
            raise ApiError('idempotency_key_required')
        value = request.get_json()
        if fingerprint is not None:
            value = {'body': value, 'precondition': fingerprint}
        body_hash = digest(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')))
        row = db.execute('SELECT * FROM idempotency WHERE owner_id=? AND path=? AND request_key=?',
                         (owner, request.path, key)).fetchone()
        if row:
            if row['expires_at'] <= self.now():
                raise ApiError('idempotency_expired', 409)
            if row['body_hash'] != body_hash:
                raise ApiError('idempotency_conflict', 409)
            return json.loads(row['response']), row['status']
        payload, status, expires = action()
        db.execute('INSERT INTO idempotency VALUES (?,?,?,?,?,?,?)',
                   (owner, request.path, key, body_hash, json.dumps(payload), status, expires))
        return payload, status

    def operation(self, db, grant_id, action, reason, actor, deadline):
        op = uid()
        db.execute('INSERT INTO operations VALUES (?,?,?,?,?,?,0,?,NULL,?,?)',
                   (op, grant_id, action, reason, actor, 'queued', self.now(), g.correlation if request else uid(), deadline))
        return op

    def status(self, row):
        r = dict(row)
        auth = r['authorization_status']
        if auth == 'accepted' and r['original_expires_at'] is not None and self.now() >= r['original_expires_at']:
            auth = 'expired'
        obs = r['observation_state']
        if r['last_observed_at'] is not None and self.now() - r['last_observed_at'] >= 30:
            obs = 'stale'
        display = 'revoked' if auth == 'revoked' else 'expired' if auth == 'expired' else 'rejected' if auth == 'rejected' else 'waiting_auth'
        # Without core-rt an accepted DB row is never sufficient evidence for connected. With it, accepted means
        # core-rt confirmed the address in PORTAL-AUTHED; only guest grants ('ipv4:') are ever sent there.
        guest = bool(self.network) and r['connection_ref'].startswith('ipv4:')
        verified = guest and auth == 'accepted'
        if guest:
            display = 'connected' if verified else 'connecting' if auth == 'pending' else display
        return dict(grant_id=r['id'], consent_id=r['consent_id'], authorization_status=auth,
                    observation_state=obs, revocation_state=r['revocation_state'], display_state=display,
                    original_expires_at_utc=utc(r['original_expires_at']) if r['original_expires_at'] else None,
                    network_verified=verified, adapter=self.adapter_name)

    def guest_ref(self):
        """'ipv4:<address>' of the visitor's device as core-rt sees it, or None outside the guest networks."""
        if not self.network:
            return None
        from network_access import source_ref
        return source_ref(self.network.settings, request.remote_addr)


def create_app(home, clock=time.time):
    s = Service(home, clock)
    app = Flask(__name__)
    hosts=[urlsplit(s.transport[k]).hostname for k in ('portal_origin','admin_origin')] if s.transport['enabled'] else ['127.0.0.1']
    app.config.update(MAX_CONTENT_LENGTH=65536, TRUSTED_HOSTS=hosts, TESTING=False)
    if s.transport['enabled']:
        from transport import HTTPSBoundary
        app.wsgi_app=HTTPSBoundary(app.wsgi_app,s.transport)
    app.extensions['service'] = s

    def auth(kind='visitor', permission=None):
        def deco(fn):
            @wraps(fn)
            def wrapped(*args, **kwargs):
                session = s.get_session(kind)
                if not session or (kind == 'admin' and session['kind'] != 'admin'):
                    raise ApiError('authentication_required', 401, 'ログインが必要です。')
                if permission and session['admin']['role'] not in PERMISSIONS[permission]:
                    raise ApiError('permission_denied', 403, 'この操作の権限がありません。')
                if request.method != 'GET':
                    s.check_csrf(session)
                g.session = session
                g.required_permission = permission
                from workflow_generation import require_runtime_ready
                try: require_runtime_ready(s)
                except ValueError: raise ApiError('schema5_recovery_required',503,'復旧後の確認が必要です。サーバー担当へ連絡してください。')
                return fn(*args, **kwargs)
            return wrapped
        return deco

    def body(fields):
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) != set(fields):
            raise ApiError('invalid_fields')
        return data

    def cookie(response, raw, kind):
        name = 'admin_session' if kind == 'admin' else 'portal_session'
        ttl = s.config['admin_session_seconds' if kind == 'admin' else 'visitor_session_seconds']
        response.set_cookie(name, raw, max_age=ttl, httponly=True, samesite='Strict', secure=s.transport['enabled'], path='/')
        return response

    @app.before_request
    def boundary():
        g.correlation = uid()
        from transport import request_origin
        expected=request_origin(s.config,request.path)
        if request.path.startswith('/static/') and s.transport['enabled']:
            expected=request.host_url.rstrip('/') if request.host_url.rstrip('/') in (s.transport['portal_origin'],s.transport['admin_origin']) else expected
        if request.host_url.rstrip('/') != expected:
            raise ApiError('host_invalid', 400)
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            if request.headers.get('Origin') != expected:
                raise ApiError('origin_invalid', 403)
            if not request.is_json:
                raise ApiError('json_required', 415)

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response.headers['X-Correlation-ID'] = g.get('correlation', uid())
        if s.transport['enabled']:
            response.headers['Strict-Transport-Security']='max-age=3600'
        return response

    @app.errorhandler(ApiError)
    def api_error(e):
        response = jsonify(code=e.code, message=e.message, retryable=e.status in (429, 503) and e.code != 'session_capacity_exhausted', correlation_id=g.get('correlation'))
        response.status_code = e.status
        if e.status == 429:
            response.headers['Retry-After'] = str(e.retry_after if e.retry_after is not None else 900)
        elif e.retry_after is not None:
            response.headers['Retry-After'] = str(e.retry_after)
        return response

    @app.errorhandler(GuardRejected)
    def session_guard_error(e):
        # No peer address, cookie, token, counters or capacity totals in the body.
        return api_error(ApiError(e.code, e.status, retry_after=e.retry_after))

    @app.errorhandler(HTTPException)
    def http_error(e):
        return api_error(ApiError('http_' + str(e.code), e.code))

    @app.errorhandler(Exception)
    def unexpected(e):
        # Never log request data, token, password, SQL, or exception text.
        app.logger.error('request_failed correlation=%s type=%s', g.get('correlation'), type(e).__name__)
        return api_error(ApiError('internal_error', 500, '処理できませんでした。運営者に確認してください。'))

    @app.get('/')
    def portal():
        return render_template('portal.html')

    @app.get('/capport/api')
    def capport():
        # RFC 8908 Captive Portal API. Without core-rt integration no client is ever released, so every client stays captive.
        from transport import request_origin
        value = {'captive': True, 'user-portal-url': request_origin(s.config, '/') + '/'}
        ref = s.guest_ref()
        if ref:
            with s.db() as db:
                row = db.execute("SELECT max(original_expires_at) AS until FROM grants WHERE connection_ref=? AND authorization_status='accepted' AND original_expires_at>?",
                                 (ref, s.now())).fetchone()
            if row and row['until']:
                value.update({'captive': False, 'seconds-remaining': int(row['until']) - s.now()})
        response = jsonify(value)
        response.content_type = 'application/captive+json'
        return response

    @app.get('/admin')
    def admin_page():
        return render_template('admin.html')

    @app.get('/health/live')
    def live():
        return jsonify(status='alive', production_enabled=False, adapter=s.adapter_name)

    @app.get('/health/ready')
    def ready():
        try:
            with s.db() as db:
                db.execute('SELECT 1').fetchone()
            return jsonify(status='local_ready', production_ready=False)
        except DatabaseError:
            raise ApiError('database_unavailable', 503)

    @app.get('/health/jobs')
    def jobs_health():
        with s.db() as db:
            row = db.execute("SELECT value FROM meta WHERE name='last_job_at'").fetchone()
        fresh = not worker_status(row[0] if row else None,s.now())['stale']
        return jsonify(status='ok' if fresh else 'worker_stale'), 200 if fresh else 503

    @app.get('/v1/public')
    def public():
        lang = request.args.get('lang', 'ja')
        if lang not in ('ja', 'en'):
            raise ApiError('language_unsupported')
        try:
            s.intake()
            state = 'local_only'
        except ApiError as e:
            state = e.code
        from event_information import public as display_information
        return jsonify(mode='local', production_enabled=False, service_state=state, adapter=s.adapter_name, terms=s.public_terms(lang),event_information=display_information(s.config),daily_service_hours=s.config.get('daily_service_hours'))

    @app.route('/v1/admin/session', methods=['GET', 'POST'])
    @app.post('/v1/session')
    def bootstrap():
        kind = 'admin' if '/admin/' in request.path else 'visitor'
        try:
            peer = ipaddress.ip_address(request.remote_addr or '')
        except ValueError:
            raise GuardRejected('session_source_unavailable', status=503)
        if isinstance(peer, ipaddress.IPv6Address) and peer.ipv4_mapped:
            peer = peer.ipv4_mapped
        source_key = s.pseudonym('session-source:' + str(peer))
        # Runs before get_session opens a DB connection, including invalid cookies.
        s.session_guard.bootstrap.admit(source_key)
        session = s.get_session(kind)
        if request.method != 'POST' and not session:
            raise ApiError('authentication_required', 401)
        if not session:
            s.session_guard.issue.admit(source_key)
            with s.db(True) as db:
                raw = s.new_session(db, 'admin_pre' if kind == 'admin' else 'visitor', uid())
            response = jsonify(csrf_token=s.csrf(raw), authenticated=False)
            return cookie(response, raw, kind)
        return jsonify(csrf_token=s.csrf(session['raw']), authenticated=session['kind'] == 'admin',
                       mfa_required=session['kind']=='admin_mfa',user=session.get('admin') if session['kind']=='admin' else None)

    @app.post('/v1/admin/login')
    def login():
        session = s.get_session('admin')
        s.check_csrf(session)
        data = body(('username', 'password'))
        if not isinstance(data['username'], str) or not isinstance(data['password'], str):
            raise ApiError('invalid_fields')
        if len(data['username']) > 80 or len(data['password']) > 256:
            raise ApiError('credentials_invalid', 401)
        name = data['username'].strip().lower()
        buckets = [(s.pseudonym('user:' + name), 5), (s.pseudonym('ip:' + (request.remote_addr or '')), 100)]
        limited = False
        valid = False
        with s.db(True) as db:
            db.execute('DELETE FROM login_limits WHERE expires_at<=?', (s.now(),))
            for bucket, limit in buckets:
                row = db.execute('SELECT count FROM login_limits WHERE bucket=?', (bucket,)).fetchone()
                if row and row['count'] >= limit:
                    limited = True
            if not limited:
                a = db.execute('SELECT * FROM admins WHERE username=?', (name,)).fetchone()
                candidate = a['password_hash'] if a else app.config['DUMMY_HASH']
                valid = check_password_hash(candidate, data['password']) and bool(a) and bool(a['enabled'])
                if valid:
                    db.execute('DELETE FROM sessions WHERE token_hash=?', (session['token_hash'],))
                    mfa=db.execute('SELECT enabled FROM mfa_settings WHERE admin_id=?',(a['id'],)).fetchone()
                    needs_mfa=bool(mfa and mfa['enabled'])
                    raw = s.new_session(db, 'admin_mfa' if needs_mfa else 'admin', a['id'])
                    if needs_mfa:
                        db.execute('UPDATE sessions SET expires_at=? WHERE token_hash=?',(s.now()+120,digest(raw)))
                    else: s.audit(db, a['id'], 'login')
                    db.execute('DELETE FROM login_limits WHERE bucket=?', (buckets[0][0],))
                else:
                    for bucket, _ in buckets:
                        db.execute('INSERT INTO login_limits VALUES (?,1,?) ON DUPLICATE KEY UPDATE count=count+1',
                                   (bucket, s.now() + 900))
                    s.audit(db, 'anonymous', 'login_failed')
        if limited:
            raise ApiError('login_rate_limited', 429)
        if not valid:
            raise ApiError('credentials_invalid', 401, '利用者名またはパスワードを確認してください。')
        return cookie(jsonify(authenticated=not needs_mfa,mfa_required=needs_mfa,csrf_token=s.csrf(raw),
                              user=None if needs_mfa else {'username': a['username'], 'role': a['role']}),raw,'admin')

    app.config['DUMMY_HASH'] = generate_password_hash(secrets.token_urlsafe(32), method='scrypt')

    @app.post('/v1/admin/logout')
    @auth('admin')
    def logout():
        body(())
        with s.db(True) as db:
            db.execute('DELETE FROM sessions WHERE token_hash=?', (g.session['token_hash'],))
            s.audit(db, g.session['owner_id'], 'logout')
        r = jsonify(ok=True)
        r.delete_cookie('admin_session', path='/', httponly=True, samesite='Strict', secure=s.transport['enabled'])
        return r

    @app.post('/v1/contexts')
    @auth()
    def contexts():
        data = body(('launch_ref',))
        if data['launch_ref'] is None:
            # Guests redirected by core-rt have no per-visitor link; the device is told apart by its address.
            if not s.network:
                raise ApiError('source_entry_unavailable', 403)
            s.intake()
            ref = s.guest_ref()
            if not ref:
                raise ApiError('source_outside_guest', 403, 'ゲストWi-Fiの端末として確認できません。Wi-Fiにつなぎ直すか、運営スタッフへお声がけください。')
            with s.db(True) as db:
                def from_source():
                    context = uid()
                    deadline = min(s.now() + 300, timestamp(s.config['service_end_utc']))
                    db.execute('INSERT INTO contexts VALUES (?,?,?,?)', (context, g.session['owner_id'], ref, deadline))
                    return {'context_id': context, 'mode': 'local'}, 201, deadline
                return s.idempotent(db, g.session['owner_id'], from_source)
        s.intake()
        if not isinstance(data['launch_ref'], str) or len(data['launch_ref']) > 128:
            raise ApiError('launch_invalid', 403)
        with s.db(True) as db:
            def action():
                launch = db.execute('SELECT * FROM launches WHERE token_hash=? AND expires_at>?',
                                    (digest(data['launch_ref']), s.now())).fetchone()
                if not launch or (launch['owner_id'] and launch['owner_id'] != g.session['owner_id']):
                    raise ApiError('launch_invalid', 403)
                if launch['context_id']:
                    return {'context_id': launch['context_id'], 'mode': 'local'}, 200, launch['expires_at']
                context = uid()
                deadline = min(s.now() + 300, timestamp(s.config['service_end_utc']))
                db.execute('INSERT INTO contexts VALUES (?,?,?,?)', (context, g.session['owner_id'], launch['connection_ref'], deadline))
                db.execute('UPDATE launches SET owner_id=?,context_id=? WHERE token_hash=?',
                           (g.session['owner_id'], context, digest(data['launch_ref'])))
                return {'context_id': context, 'mode': 'local'}, 201, deadline
            return s.idempotent(db, g.session['owner_id'], action)

    @app.get('/v1/contexts/<context_id>')
    @auth()
    def context_get(context_id):
        s.intake()
        lang = request.args.get('lang', 'ja')
        if lang not in ('ja', 'en'):
            raise ApiError('language_unsupported')
        with s.db() as db:
            c = db.execute('SELECT * FROM contexts WHERE id=? AND owner_id=? AND expires_at>?',
                           (context_id, g.session['owner_id'], s.now())).fetchone()
        if not c:
            raise ApiError('context_not_found', 404)
        return jsonify(context_id=context_id, mode='local', expires_at_utc=utc(c['expires_at']), terms=s.terms(lang))

    @app.post('/v1/consents')
    @auth()
    def consent_post():
        d = body(('context_id', 'accepted', 'terms_document_id', 'terms_sha256', 'policy_version', 'language'))
        if d['accepted'] is not True or d['language'] not in ('ja', 'en'):
            raise ApiError('consent_invalid')
        if any(not isinstance(d[k], str) for k in ('context_id', 'terms_document_id', 'terms_sha256', 'policy_version')):
            raise ApiError('invalid_fields')
        with s.db(True) as db:
            def action():
                # Only new requests depend on the current window and published terms.
                # Authentication/CSRF and the exact request shape still precede replay.
                s.intake()
                t = s.terms(d['language'],db)
                if (d['terms_document_id'], d['terms_sha256'], d['policy_version']) != (t['document_id'], t['sha256'], t['policy_version']):
                    raise ApiError('terms_changed', 409)
                c = db.execute('SELECT * FROM contexts WHERE id=? AND owner_id=? AND expires_at>?',
                               (d['context_id'], g.session['owner_id'], s.now())).fetchone()
                if not c:
                    raise ApiError('context_not_found', 404)
                guest = c['connection_ref'].startswith('ipv4:')
                if guest and c['connection_ref'] != s.guest_ref():
                    # core-rt releases the address the context was opened from; another address must open its own page.
                    raise ApiError('source_changed', 409, 'Wi-Fiの接続が変わりました。画面を開き直してください。')
                # Contexts cannot create multiple grants using different retry keys. A guest may consent again
                # once the earlier grant has ended (expired, revoked or not connected).
                existing = db.execute('SELECT * FROM grants WHERE owner_id=? AND connection_ref=?' + (
                                      " AND (authorization_status='pending' OR (authorization_status='accepted' AND original_expires_at>?))" if guest else ''),
                                      (g.session['owner_id'], c['connection_ref']) + ((s.now(),) if guest else ())).fetchone()
                if existing:
                    saved = db.execute('SELECT * FROM consents WHERE id=?', (existing['consent_id'],)).fetchone()
                    if (saved['language'], saved['terms_sha256'], saved['policy_version']) != (d['language'], t['sha256'], t['policy_version']):
                        raise ApiError('context_already_consented', 409)
                    return s.status(existing), 200, existing['delete_after']
                consent_id, grant_id, deadline = uid(), uid(), s.record_deadline()
                db.execute('INSERT INTO consents (id,event_id,service_window_id,terms_document_id,terms_version,terms_sha256,policy_version,accepted_at_utc,language,accepted,consent_method,connection_ref,request_id,delete_after) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                           (consent_id, s.config['event_id'], s.config['service_window_id'], t['document_id'], t['version'],
                            t['sha256'], t['policy_version'], utc(s.now()), d['language'], 1, 'checkbox_and_submit',
                            c['connection_ref'], g.correlation, deadline))
                db.execute('INSERT INTO grants (id,consent_id,owner_id,connection_ref,authorization_status,observation_state,revocation_state,authorized_at,original_expires_at,last_observed_at,revoked_at,delete_after,row_version) VALUES (?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,?,1)',
                           (grant_id, consent_id, g.session['owner_id'], c['connection_ref'], 'pending', 'unknown', 'none', deadline))
                # The INSERT has no network permission side effects.
                op = s.operation(db, grant_id, 'authorize', 'consent_saved', 'visitor', deadline)
                s.audit(db, 'visitor', 'consent_created', consent_id)
                r = s.status(db.execute('SELECT * FROM grants WHERE id=?', (grant_id,)).fetchone())
                r['operation_id'] = op
                return r, 201, deadline
            result = s.idempotent(db, g.session['owner_id'], action)
        if s.network:
            s.network.wake()
        return result

    def owned_grant(grant_id):
        with s.db() as db:
            row = db.execute('SELECT * FROM grants WHERE id=? AND owner_id=? AND delete_after>?', (grant_id, g.session['owner_id'], s.now())).fetchone()
        if not row:
            raise ApiError('grant_not_found', 404)
        return row

    @app.get('/v1/grants/<grant_id>')
    @auth()
    def grant_get(grant_id):
        return jsonify(s.status(owned_grant(grant_id)))

    @app.post('/v1/grants/<grant_id>/handoffs')
    @auth()
    def handoff(grant_id):
        body(())
        owned_grant(grant_id)
        raise ApiError('adapter_unavailable', 503, '同意記録は保存済みですが、AP連携は未接続です。通信許可は発行していません。')

    @app.get('/v1/admin/overview')
    @auth('admin', 'read')
    def overview():
        with s.db() as db:
            counts = {table: db.execute('SELECT count(*) FROM ' + table).fetchone()[0]
                      for table in ('consents', 'grants')}
            counts['unconfirmed'] = db.execute("SELECT count(*) FROM operations WHERE status NOT IN ('confirmed')").fetchone()[0]
            if s.network:
                # Devices core-rt currently lets through, and guest operations that failed or are being retried.
                counts['network_authorized'] = db.execute("SELECT count(DISTINCT connection_ref) FROM grants WHERE authorization_status='accepted' AND original_expires_at>? AND connection_ref LIKE ?",
                                                          (s.now(), 'ipv4:%')).fetchone()[0]
                counts['network_failed'] = db.execute("SELECT count(*) FROM operations o JOIN grants g ON g.id=o.grant_id WHERE g.connection_ref LIKE ? AND (o.status='failed' OR (o.status='queued' AND o.last_error_code IS NOT NULL))",
                                                      ('ipv4:%',)).fetchone()[0]
            jobs = db.execute("SELECT value FROM meta WHERE name='last_job_at'").fetchone()
            backup = db.execute("SELECT value FROM meta WHERE name='last_backup_at'").fetchone()
        checked_at=s.now()
        worker=worker_status(jobs[0] if jobs else None,checked_at)
        try:
            s.intake()
            intake = 'local_only'
        except ApiError as e:
            intake = e.code
        return jsonify(mode='local', production_enabled=False, adapter=s.adapter_name, counts=counts,
                       server_now_utc=utc(checked_at),session_expires_at_utc=utc(g.session['expires_at']),
                       user=g.session['admin'], service_state=intake, last_job_at_utc=worker['last_success_utc'],
                       worker_stale=worker['stale'],
                       last_backup_at_utc=utc(int(backup[0])) if backup else None,
                       automatic_deletion_enabled=False, retention_days=s.config['retention_days'], backup_retention_days=s.config['backup_retention_days'])

    from usage_summary import register as register_usage
    register_usage(app,s,auth)
    from event_information import register as register_information
    register_information(app,s,auth,body)

    @app.get('/v1/admin/session-status')
    @auth('admin','read')
    def session_status():return jsonify(server_now_utc=utc(s.now()),expires_at_utc=utc(g.session['expires_at']),automatically_extended=False)

    @app.get('/v1/admin/grants')
    @auth('admin', 'operate')
    def grants_list():
        with s.db() as db:
            rows = db.execute('SELECT * FROM grants ORDER BY seq DESC LIMIT 100').fetchall()
        return jsonify(items=[s.status(r) for r in rows], limit=100)

    @app.post('/v1/admin/grants/<grant_id>/revocations')
    @auth('admin', 'operate')
    def revoke(grant_id):
        d = body(('reason',))
        if d['reason'] not in ('operator_request', 'abuse', 'service_end'):
            raise ApiError('reason_invalid')
        with s.db(True) as db:
            def action():
                row = db.execute('SELECT * FROM grants WHERE id=?', (grant_id,)).fetchone()
                if not row:
                    raise ApiError('grant_not_found', 404)
                existing = db.execute("SELECT id FROM operations WHERE grant_id=? AND action='disconnect'", (grant_id,)).fetchone()
                if existing:
                    return {'operation_id': existing['id'], 'network_verified': False}, 202, row['delete_after']
                db.execute("UPDATE grants SET authorization_status='revoked',revocation_state='queued',revoked_at=?,row_version=row_version+1 WHERE id=?",
                           (s.now(), grant_id))
                op = s.operation(db, grant_id, 'disconnect', d['reason'], g.session['owner_id'], row['delete_after'])
                s.audit(db, g.session['owner_id'], 'revoke_requested', grant_id)
                return {'operation_id': op, 'network_verified': False}, 202, row['delete_after']
            result = s.idempotent(db, g.session['owner_id'], action)
        if s.network:
            s.network.wake()
        return result

    @app.get('/v1/admin/operations/<operation_id>')
    @auth('admin', 'operate')
    def operation_get(operation_id):
        with s.db() as db:
            r = db.execute('SELECT id,grant_id,action,status,attempts,last_error_code,correlation_id FROM operations WHERE id=?', (operation_id,)).fetchone()
        if not r:
            raise ApiError('operation_not_found', 404)
        return jsonify(dict(r))

    @app.get('/v1/admin/notifications')
    @auth('admin', 'read')
    def notifications():
        with s.db() as db:
            rows = db.execute("SELECT * FROM notifications WHERE state!='resolved' ORDER BY last_seen DESC LIMIT 100").fetchall()
        return jsonify(items=[dict(r) for r in rows])

    @app.post('/v1/admin/notifications/<notification_id>/acknowledgements')
    @auth('admin', 'operate')
    def acknowledge(notification_id):
        body(())
        raw_generation = request.headers.get('X-Expected-Generation', '')
        if not raw_generation:
            raise ApiError('notification_generation_required', 409, '通知一覧を更新してから、もう一度確認してください。')
        if (len(raw_generation)>16 or not raw_generation.isascii() or not raw_generation.isdecimal()
            or not 1<=int(raw_generation)<=2**53-1 or str(int(raw_generation))!=raw_generation):
            raise ApiError('invalid_fields', 400, '通知の世代を確認してください。')
        generation = int(raw_generation)
        key = request.headers.get('Idempotency-Key', '')
        try:
            if str(uuid.UUID(key)) != key:
                raise ValueError('Noncanonical UUID')
        except ValueError:
            raise ApiError('idempotency_key_required')
        with s.db(True) as db:
            def action():
                row = db.execute('SELECT generation,state FROM notifications WHERE id=?', (notification_id,)).fetchone()
                if not row:
                    raise ApiError('notification_not_found', 404)
                if row['generation'] != generation:
                    raise ApiError('notification_generation_conflict', 409, '通知が再発しています。一覧を更新して内容を確認してください。')
                if row['state'] == 'resolved':
                    raise ApiError('notification_resolved', 409, 'この通知は解消済みです。一覧を更新してください。')
                if row['state'] not in ('open', 'acknowledged'):
                    raise ApiError('notification_state_conflict', 409, '通知の状態を確認できません。一覧を更新してください。')
                if row['state'] == 'open':
                    changed = db.execute("UPDATE notifications SET state='acknowledged',acknowledged_by=?,acknowledged_at=? WHERE id=? AND generation=? AND state='open'",
                                         (g.session['owner_id'], s.now(), notification_id, generation))
                    if changed.rowcount != 1:
                        raise ApiError('notification_state_conflict', 409, '通知の状態を確認できません。一覧を更新してください。')
                    s.audit(db, g.session['owner_id'], 'notification_acknowledged', notification_id)
                return dict(ok=True), 200, s.now() + 86400
            return s.idempotent(db, g.session['owner_id'], action,
                                fingerprint={'notification_generation': generation})

    @app.get('/v1/admin/consents/export')
    @auth('admin', 'records')
    def export():
        # A fixed maximum avoids an unbounded in-memory export. Pagination uses an immutable sequence.
        try:
            after = int(request.args.get('after', '0'))
            if after < 0:
                raise ValueError()
        except ValueError:
            raise ApiError('cursor_invalid')
        with s.db() as db:
            s.require_admin_transaction(db,g.session,'records')
            rows = db.execute('SELECT * FROM consents WHERE seq>? AND delete_after>? ORDER BY seq LIMIT 1000', (after, s.now())).fetchall()
        def safe(value):
            val = str(value)
            return "'" + val if val.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')) else val
        out = io.StringIO(newline='')
        fields = ['id', 'event_id', 'terms_version', 'terms_sha256', 'policy_version', 'accepted_at_utc', 'language', 'delete_after']
        writer = csv.writer(out)
        writer.writerow(fields)
        for row in rows:
            writer.writerow([safe(row[k]) for k in fields])
        with s.db(True) as db:
            s.require_admin_transaction(db,g.session,'records')
            from workflow_generation import require_runtime_ready
            require_runtime_ready(s,db)
            s.audit(db,g.session['owner_id'],'consents_export')
        resp = make_response('\ufeff' + out.getvalue())
        resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
        resp.headers['Content-Disposition'] = 'attachment; filename="consents.csv"'
        resp.headers['X-Next-Cursor'] = str(rows[-1]['seq']) if len(rows) == 1000 else ''
        return resp

    @app.get('/v1/admin/settings')
    @auth('admin', 'settings')
    def settings():
        c = s.config
        result={k: c[k] for k in ('mode', 'production_enabled', 'automatic_deletion_enabled', 'local_intake_enabled', 'origin', 'event_id',
                       'service_start_utc', 'service_end_utc', 'policy_version', 'terms_version', 'retention_days',
                       'backup_retention_days', 'audit_retention_days', 'production_readiness')}
        current=s.terms('ja')
        result.update(terms_version=current['version'],policy_version=current['policy_version'])
        return jsonify(result)

    @app.get('/v1/admin/users')
    @auth('admin', 'settings')
    def users():
        with s.db() as db:
            rows = db.execute('SELECT id,username,role,enabled FROM admins ORDER BY username').fetchall()
        return jsonify(items=[dict(r) for r in rows])

    from operations import register_operations
    register_operations(app,s,auth,body)
    from operator_features import register_features
    from mfa import register_mfa
    register_features(app,s,auth,body)
    register_mfa(app,s,body,cookie)
    from readiness import register_readiness
    register_readiness(app,s,auth,body)
    from archive_exports import register as register_archives
    from workflow_alerts import register as register_workflow_alerts
    register_archives(app,s,auth)
    register_workflow_alerts(app,s,auth)
    return app
