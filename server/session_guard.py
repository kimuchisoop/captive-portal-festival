"""Bounded, process-local bootstrap admission plus a retained-row safety ceiling.

Local candidate defaults, not approved festival capacity values. No persistent
rate records, raw addresses, background work, automatic retries or record purges.
"""
from collections import deque, OrderedDict
import math
import threading
import time

WINDOW_SECONDS = 60
BOOTSTRAP_SOURCE_LIMIT = 120
BOOTSTRAP_GLOBAL_LIMIT = 600
ISSUE_SOURCE_LIMIT = 20
ISSUE_GLOBAL_LIMIT = 120
SOURCE_SLOTS = 2048
MAX_RETAINED_SESSION_ROWS = 100000


class GuardRejected(Exception):
    def __init__(self, code, status=429, retry_after=WINDOW_SECONDS):
        self.code = code
        self.status = status
        self.retry_after = retry_after


class SlidingWindow:
    def __init__(self, source_limit, global_limit, code, clock=time.monotonic):
        self._source_limit = source_limit
        self._global_limit = global_limit
        self._code = code
        self._clock = clock
        self._lock = threading.Lock()
        self._sources = OrderedDict()
        self._global = deque()

    def admit(self, source_key):
        # The caller supplies a purpose-separated HMAC of the trusted peer.
        with self._lock:
            now = self._clock()
            cutoff = now - WINDOW_SECONDS
            while self._global and self._global[0] <= cutoff:
                self._global.popleft()
            # Keys follow their last admitted timestamp. Only the expired prefix
            # can be reclaimed; active sources are never evicted to admit others.
            while self._sources:
                oldest = next(iter(self._sources.values()))
                if oldest[-1] > cutoff:
                    break
                self._sources.popitem(last=False)
            local = self._sources.get(source_key)
            if local is not None:
                while local and local[0] <= cutoff:
                    local.popleft()
            waits = []
            if len(self._global) >= self._global_limit:
                waits.append(self._global[0] + WINDOW_SECONDS - now)
            if local is not None and len(local) >= self._source_limit:
                waits.append(local[0] + WINDOW_SECONDS - now)
            if waits:
                raise GuardRejected(self._code, retry_after=min(WINDOW_SECONDS, max(1, math.ceil(max(waits)))))
            if local is None:
                if len(self._sources) >= SOURCE_SLOTS:
                    raise GuardRejected('session_guard_capacity', status=503)
                local = deque()
                self._sources[source_key] = local
            local.append(now)
            self._sources.move_to_end(source_key)
            self._global.append(now)


class SessionIssueGuard:
    def __init__(self):
        # Shared by admin and visitor paths; cookie removal does not reset a key.
        self.bootstrap = SlidingWindow(BOOTSTRAP_SOURCE_LIMIT, BOOTSTRAP_GLOBAL_LIMIT,
                                       'session_bootstrap_rate_limited')
        self.issue = SlidingWindow(ISSUE_SOURCE_LIMIT, ISSUE_GLOBAL_LIMIT,
                                   'session_issue_rate_limited')


def require_storage_capacity(db):
    # Called inside the existing serialized write transaction before every INSERT.
    # A bounded primary-index scan counts retained rows, including expired rows.
    # Never DELETE/UPDATE evidence or reserve an unbounded new counter table.
    if db.execute('SELECT token_hash FROM sessions LIMIT ?,1',
                  (MAX_RETAINED_SESSION_ROWS - 1,)).fetchone() is not None:
        raise GuardRejected('session_capacity_exhausted', status=503, retry_after=None)
