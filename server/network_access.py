"""Stage 3: carries queued grant operations to core-rt's PORTAL-AUTHED group (guide 16.5).

Off unless config.json has vyos_portal.enabled=true. Only grants whose connection_ref is 'ipv4:<guest address>'
are handled here; local review grants keep the disconnected behaviour in jobs.housekeeping.
Router calls never run inside a DB transaction, and one MySQL named lock keeps the serve loop and the worker
from changing the group at the same time.
"""
import ipaddress
import logging
import threading
import time
from pathlib import Path

from vyos_gateway import VyosGateway, GatewayError, GatewayRefused, GatewayRejected, GatewayUnavailable

FIELDS = {'enabled', 'api_origin', 'api_key_file', 'ca_file', 'guest_networks', 'access_seconds'}
PREFIX = 'ipv4:'
LOCK = 'festival_wifi_portal_authed'
LEASE = 30              # a claimed operation is retried after this if its run never finished
AUTHORIZE_ATTEMPTS = 3  # then the visitor sees "not connected" and staff are notified
ALLOW_RETRY = 5
REVOKE_RETRY = 30
BATCH = 500
BATCH_WINDOW = 1.0      # collect a second of consents into one VyOS commit


def plain_name(value, key):
    if not isinstance(value, str) or not value or Path(value).name != value or value in ('.', '..'):
        raise ValueError(f'vyos_portal.{key} must be a file name inside the data folder')
    return value


def validate(config, home):
    """Returns the settings when enabled, None when disabled; raises ValueError on anything doubtful."""
    data = config.get('vyos_portal')
    if data is None:
        return None
    if not isinstance(data, dict) or set(data) != FIELDS or type(data['enabled']) is not bool:
        raise ValueError('Invalid vyos_portal settings')
    if not data['enabled']:
        return None
    if config.get('https_transport', {}).get('enabled') is not True:
        # Without the proxy boundary the app only listens on loopback and never sees a guest address.
        raise ValueError('vyos_portal needs https_transport enabled')
    plain_name(data['api_key_file'], 'api_key_file')
    if not (Path(home) / data['api_key_file']).is_file():
        raise ValueError('vyos_portal.api_key_file missing')
    if data['ca_file'] is not None:
        plain_name(data['ca_file'], 'ca_file')
        if not (Path(home) / data['ca_file']).is_file():
            raise ValueError('vyos_portal.ca_file missing')
    try:
        networks = [ipaddress.IPv4Network(n) for n in data['guest_networks']]
    except (TypeError, ValueError):
        raise ValueError('vyos_portal.guest_networks must be IPv4 CIDR') from None
    if not networks:
        raise ValueError('vyos_portal.guest_networks missing')
    if type(data['access_seconds']) is not int or not 60 <= data['access_seconds'] <= 86400:
        raise ValueError('vyos_portal.access_seconds must be 60-86400')
    return dict(data, guest_networks=networks)


def source_ref(settings, address):
    """'ipv4:<address>' for a guest address, else None (server, management, loopback, IPv6)."""
    try:
        peer = ipaddress.ip_address(address or '')
    except ValueError:
        return None
    if isinstance(peer, ipaddress.IPv6Address):
        peer = peer.ipv4_mapped
    if peer is None or not any(peer in n for n in settings['guest_networks']):
        return None
    return PREFIX + str(peer)


def access_deadline(s, now):
    """Consent time + access_seconds, cut at today's closing time and the end of the service window (guide C14)."""
    from app import timestamp
    from daily_hours import minutes
    deadline = min(now + s.network.settings['access_seconds'], timestamp(s.config['service_end_utc']))
    hours = s.config.get('daily_service_hours')
    if hours:
        offset = hours['utc_offset_minutes'] * 60
        local_midnight = now + offset - (now + offset) % 86400
        deadline = min(deadline, local_midnight - offset + minutes(hours['close']) * 60)
    return deadline


class NetworkAccess:
    def __init__(self, s, settings):
        self.s, self.settings = s, settings
        key = (s.home / settings['api_key_file']).read_text(encoding='utf-8').strip()
        ca = str(s.home / settings['ca_file']) if settings['ca_file'] else None
        self.gateway = VyosGateway(settings['api_origin'], key, [str(n) for n in settings['guest_networks']], ca_file=ca)
        self.wakeup = threading.Event()
        self.thread = None
        self.background = True
        self.start_lock = threading.Lock()

    def wake(self):
        """Called after a consent or revocation commits; the serve process handles it within about a second."""
        if not self.background:
            return
        with self.start_lock:
            if self.thread is None:
                self.thread = threading.Thread(target=self.loop, name='portal-authed', daemon=True)
                self.thread.start()
        self.wakeup.set()

    def loop(self):
        while True:
            woken = self.wakeup.wait(2)
            if woken:
                time.sleep(BATCH_WINDOW)
            self.wakeup.clear()
            try:
                process_due(self.s)
            except Exception as error:  # Keep serving; the worker retries the same queued operations.
                logging.getLogger(__name__).error('portal_authed_failed type=%s', type(error).__name__)


def error_code(error):
    return ('gateway_refused' if isinstance(error, GatewayRefused) else 'gateway_rejected' if isinstance(error, GatewayRejected)
            else 'gateway_unavailable')


def still_authorized(db, ref, grant_id, now):
    return db.execute("SELECT 1 FROM grants WHERE connection_ref=? AND id<>? AND (authorization_status='pending' OR "
                      "(authorization_status='accepted' AND original_expires_at>?)) LIMIT 1", (ref, grant_id, now)).fetchone() is not None


def process_due(s):
    """Runs every due operation for guest grants. Returns how many operations were finished this call."""
    if not s.network:
        return 0
    finished = 0
    with s.db() as lock:
        if lock.execute('SELECT GET_LOCK(?,0) AS got', (LOCK,)).fetchone()['got'] != 1:
            return 0  # the other process is already changing the group
        try:
            while True:
                count, full = run_batch(s)
                finished += count
                if not full:
                    return finished
        finally:
            lock.execute('SELECT RELEASE_LOCK(?)', (LOCK,))


def grant_deadline(db, grant_id):
    return db.execute('SELECT delete_after FROM grants WHERE id=?', (grant_id,)).fetchone()['delete_after']


def run_batch(s):
    from app import uid
    from jobs import notify
    now = s.now()
    with s.db(True) as db:
        rows = db.execute("SELECT o.id,o.grant_id,o.action,o.attempts,g.connection_ref,g.authorization_status FROM operations o "
                          "JOIN grants g ON g.id=o.grant_id WHERE o.status='queued' AND o.next_attempt<=? AND g.connection_ref LIKE ? "
                          "ORDER BY o.next_attempt LIMIT " + str(BATCH) + " FOR UPDATE", (now, PREFIX + '%')).fetchall()
        for r in rows:
            db.execute('UPDATE operations SET attempts=attempts+1,next_attempt=? WHERE id=?', (now + LEASE, r['id']))
    if not rows:
        return 0, False
    gateway = s.network.gateway
    done = lambda db, r, code=None: db.execute("UPDATE operations SET status='confirmed',last_error_code=? WHERE id=?", (code, r['id']))

    # Removals first, so a device that consented again in the same batch is added back right after.
    removals = []
    with s.db() as db:
        for r in (r for r in rows if r['action'] == 'disconnect'):
            if still_authorized(db, r['connection_ref'], r['grant_id'], now):
                r['kept'] = True
            else:
                removals.append(r)
    keep = [r for r in rows if r.get('kept')]
    failure = None
    if removals:
        try:
            gateway.revoke_many([r['connection_ref'][len(PREFIX):] for r in removals])
        except GatewayError as error:
            failure = error
    with s.db(True) as db:
        for r in keep:
            done(db, r, 'still_authorized')
            db.execute("UPDATE grants SET revocation_state='confirmed',row_version=row_version+1 WHERE id=?", (r['grant_id'],))
        for r in removals:
            if failure is None:
                done(db, r)
                db.execute("UPDATE grants SET revocation_state='confirmed',row_version=row_version+1 WHERE id=?", (r['grant_id'],))
            else:
                db.execute('UPDATE operations SET next_attempt=?,last_error_code=? WHERE id=?', (now + REVOKE_RETRY, error_code(failure), r['id']))
        stuck = failure is not None and any(r['attempts'] + 1 >= 3 for r in removals)
        if removals and (stuck or failure is None):
            notify(db, now, 'portal_revoke_failed', '期限切れ・解除した端末をcore-rtの許可済みグループから外せていません。core-rtへの接続とAPIキーを確認してください。'
                   '外せるまで自動で再試行します。', stuck, severity='critical')

    adds = [r for r in rows if r['action'] == 'authorize']
    waiting = [r for r in adds if r['authorization_status'] == 'pending']
    refused, allowed = [], []
    for r in waiting:
        try:
            gateway.address(r['connection_ref'][len(PREFIX):])
            allowed.append(r)
        except GatewayRefused:
            refused.append(r)
    failure = None
    if allowed:
        try:
            gateway.allow_many([r['connection_ref'][len(PREFIX):] for r in allowed])
        except GatewayError as error:
            failure = error
    final = []
    with s.db(True) as db:
        for r in adds:
            if r not in waiting:
                done(db, r, 'not_needed')
        for r in allowed if failure is None else []:
            changed = db.execute("UPDATE grants SET authorization_status='accepted',authorized_at=?,original_expires_at=?,row_version=row_version+1 "
                                 "WHERE id=? AND authorization_status='pending'", (now, access_deadline(s, now), r['grant_id'])).rowcount
            done(db, r)
            if not changed:
                # Revoked while the router was adding it: run the removal again now that the address is in the group.
                db.execute("UPDATE operations SET status='queued',next_attempt=? WHERE grant_id=? AND action='disconnect'", (now, r['grant_id']))
        for r in refused + (allowed if failure is not None else []):
            if r in refused or r['attempts'] + 1 >= AUTHORIZE_ATTEMPTS:
                code = 'gateway_refused' if r in refused else error_code(failure)
                db.execute("UPDATE operations SET status='failed',last_error_code=? WHERE id=?", (code, r['id']))
                changed = db.execute("UPDATE grants SET authorization_status='rejected',row_version=row_version+1 WHERE id=? AND authorization_status='pending'", (r['grant_id'],)).rowcount
                if changed and isinstance(failure, GatewayUnavailable) and r not in refused and not db.execute(
                        "SELECT 1 FROM operations WHERE grant_id=? AND action='disconnect'", (r['grant_id'],)).fetchone():
                    # No answer is not "not added": the commit may have reached core-rt, so remove the address to be sure.
                    db.execute("UPDATE grants SET revocation_state='queued',row_version=row_version+1 WHERE id=?", (r['grant_id'],))
                    db.execute('INSERT INTO operations VALUES (?,?,?,?,?,?,0,?,NULL,?,?)',
                               (uid(), r['grant_id'], 'disconnect', 'allow_unconfirmed', 'worker', 'queued', now, uid(), grant_deadline(db, r['grant_id'])))
                final.append(r)
            else:
                db.execute('UPDATE operations SET next_attempt=?,last_error_code=? WHERE id=?', (now + ALLOW_RETRY, error_code(failure), r['id']))
        if final:
            notify(db, now, 'portal_allow_failed', '同意した端末をcore-rtの許可済みグループへ追加できませんでした。来場者の画面は「つながっていません」です。'
                   'core-rtへの接続とAPIキーを確認し、端末には同意し直してもらってください。', True, severity='critical')
        elif allowed and failure is None:
            notify(db, now, 'portal_allow_failed', '', False)
    return len(rows), len(rows) == BATCH
