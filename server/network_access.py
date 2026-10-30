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
GATEWAY_COMMIT_TIMEOUT = 20  # leave ten seconds before the claimed-operation lease expires
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
        self.gateway = VyosGateway(settings['api_origin'], key, [str(n) for n in settings['guest_networks']],
                                   ca_file=ca, commit_timeout=GATEWAY_COMMIT_TIMEOUT)
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


def _marks(rows):
    return ','.join('?' for _ in rows)


def _ids(rows, key='id'):
    return [r[key] for r in rows]


def _update_ids(db, sql, rows, values=()):
    if rows:
        db.execute(sql.format(marks=_marks(rows)), (*values, *_ids(rows)))


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
        _update_ids(db, 'UPDATE operations SET attempts=attempts+1,next_attempt=? WHERE id IN ({marks})', rows, (now + LEASE,))
    if not rows:
        return 0, False
    gateway = s.network.gateway
    # Removals first, so a device that consented again in the same batch is added back right after.
    disconnects = [r for r in rows if r['action'] == 'disconnect']
    refs = list(dict.fromkeys(r['connection_ref'] for r in disconnects))
    active = {}
    if refs:
        with s.db() as db:
            found = db.execute("SELECT id,connection_ref FROM grants WHERE connection_ref IN (" + _marks(refs) +
                               ") AND (authorization_status='pending' OR (authorization_status='accepted' AND original_expires_at>?))",
                               (*refs, now)).fetchall()
        for grant in found:
            active.setdefault(grant['connection_ref'], set()).add(grant['id'])
    removals = []
    for r in disconnects:
        if active.get(r['connection_ref'], set()) - {r['grant_id']}:
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
        _update_ids(db, "UPDATE operations SET status='confirmed',last_error_code='still_authorized' WHERE id IN ({marks})", keep)
        keep_grants = [{'id': r['grant_id']} for r in keep]
        _update_ids(db, "UPDATE grants SET revocation_state='confirmed',row_version=row_version+1 WHERE id IN ({marks})", keep_grants)
        if failure is None:
            _update_ids(db, "UPDATE operations SET status='confirmed',last_error_code=NULL WHERE id IN ({marks})", removals)
            remove_grants = [{'id': r['grant_id']} for r in removals]
            _update_ids(db, "UPDATE grants SET revocation_state='confirmed',row_version=row_version+1 WHERE id IN ({marks})", remove_grants)
        else:
            _update_ids(db, 'UPDATE operations SET next_attempt=?,last_error_code=? WHERE id IN ({marks})', removals,
                        (now + REVOKE_RETRY, error_code(failure)))
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
        not_needed = [r for r in adds if r not in waiting]
        _update_ids(db, "UPDATE operations SET status='confirmed',last_error_code='not_needed' WHERE id IN ({marks})", not_needed)
        if allowed and failure is None:
            deadline = access_deadline(s, now)
            grant_ids = [r['grant_id'] for r in allowed]
            marks = _marks(grant_ids)
            db.execute("UPDATE grants SET authorization_status='accepted',authorized_at=?,original_expires_at=?,row_version=row_version+1 "
                       f"WHERE id IN ({marks}) AND authorization_status='pending'", (now, deadline, *grant_ids))
            _update_ids(db, "UPDATE operations SET status='confirmed',last_error_code=NULL WHERE id IN ({marks})", allowed)
            current = {r['id']: r['authorization_status'] for r in db.execute(
                f'SELECT id,authorization_status FROM grants WHERE id IN ({marks})', tuple(grant_ids)).fetchall()}
            stale = [r for r in allowed if current.get(r['grant_id']) != 'accepted']
            if stale:
                grant_ids = [r['grant_id'] for r in stale]
                marks = _marks(grant_ids)
                db.execute(f"UPDATE operations SET status='queued',next_attempt=? WHERE action='disconnect' AND grant_id IN ({marks})",
                           (now, *grant_ids))
        failed = refused + (allowed if failure is not None else [])
        final = [r for r in failed if r in refused or r['attempts'] + 1 >= AUTHORIZE_ATTEMPTS]
        retry = [r for r in failed if r not in final]
        if refused:
            _update_ids(db, "UPDATE operations SET status='failed',last_error_code='gateway_refused' WHERE id IN ({marks})", refused)
            refused_grants = [{'id': r['grant_id']} for r in refused]
            _update_ids(db, "UPDATE grants SET authorization_status='rejected',row_version=row_version+1 WHERE id IN ({marks}) AND authorization_status='pending'", refused_grants)
        failed_gateway = [r for r in final if r not in refused]
        if failed_gateway:
            code = error_code(failure)
            _update_ids(db, 'UPDATE operations SET status=\'failed\',last_error_code=? WHERE id IN ({marks})', failed_gateway, (code,))
            failed_grants = [{'id': r['grant_id']} for r in failed_gateway]
            pending_ids = [r['id'] for r in db.execute(
                f"SELECT id FROM grants WHERE id IN ({_marks(failed_grants)}) AND authorization_status='pending'",
                tuple(_ids(failed_grants))).fetchall()]
            _update_ids(db, "UPDATE grants SET authorization_status='rejected',row_version=row_version+1 WHERE id IN ({marks}) AND authorization_status='pending'", failed_grants)
            if isinstance(failure, GatewayUnavailable) and pending_ids:
                # An unacknowledged commit may have reached core-rt; queue cleanup for every unconfirmed address.
                pending = [{'id': grant_id} for grant_id in pending_ids]
                _update_ids(db, "UPDATE grants SET revocation_state='queued',row_version=row_version+1 WHERE id IN ({marks})", pending)
                existing = {r['grant_id'] for r in db.execute(
                    f"SELECT grant_id FROM operations WHERE action='disconnect' AND grant_id IN ({_marks(pending_ids)})",
                    tuple(pending_ids)).fetchall()}
                for r in failed_gateway:
                    if r['grant_id'] not in pending_ids or r['grant_id'] in existing:continue
                    db.execute('INSERT INTO operations VALUES (?,?,?,?,?,?,0,?,NULL,?,?)',
                               (uid(), r['grant_id'], 'disconnect', 'allow_unconfirmed', 'worker', 'queued', now, uid(), grant_deadline(db, r['grant_id'])))
        if retry:
            _update_ids(db, 'UPDATE operations SET next_attempt=?,last_error_code=? WHERE id IN ({marks})', retry,
                        (now + ALLOW_RETRY, error_code(failure)))
        if final:
            notify(db, now, 'portal_allow_failed', '同意した端末をcore-rtの許可済みグループへ追加できませんでした。来場者の画面は「つながっていません」です。'
                   'core-rtへの接続とAPIキーを確認し、端末には同意し直してもらってください。', True, severity='critical')
        elif allowed and failure is None:
            notify(db, now, 'portal_allow_failed', '', False)
    return len(rows), len(rows) == BATCH
