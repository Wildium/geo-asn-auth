"""
Config lifecycle: holds the live Config and hot-reloads it when the file
changes (mtime poll) or on demand (admin API writes, SIGHUP).

Reload safety contract (issue #3):
- A failed reload (malformed YAML, bad rules) keeps serving the last-good config.
- The service never crashes or fails-open due to a config typo.
- Reload status is exposed for /health and the admin API.
"""

import logging
import os
import threading
import time

from .config import Config

logger = logging.getLogger(__name__)

POLL_INTERVAL = float(os.getenv('CONFIG_POLL_INTERVAL', '2.0'))
# Floor between recovery retries while no config is loaded. Without it, a
# broken remote list makes every poll (2s) rebuild Config inline on the
# request path — up to FETCH_BUDGET_S of network per try, forever.
RETRY_INTERVAL = float(os.getenv('CONFIG_RETRY_INTERVAL', '10.0'))


class ConfigManager:
    """Owns the current Config; reloads on file change or explicit request."""

    def __init__(self, config_path=None, poll_interval=None):
        self._lock = threading.Lock()
        self._config = None
        self._path = config_path
        self._poll_interval = poll_interval if poll_interval is not None else POLL_INTERVAL
        self._last_check = 0.0
        self._last_mtime = None
        self._last_size = None
        self.last_reload = None
        self.last_reload_error = None
        self.reload_count = 0
        self.config_loaded = False
        self._last_attempt = 0.0
        self._load_initial()

    # ------------------------------------------------------------------ #
    # Path resolution (read at call time so tests/env changes apply)
    # ------------------------------------------------------------------ #
    def config_path(self):
        return self._path or os.getenv('CONFIG_PATH', '/app/config.yaml')

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def current(self):
        """Return the live Config, reloading first if the file changed."""
        now = time.monotonic()
        if now - self._last_check >= self._poll_interval:
            self._last_check = now
            if self._file_changed():
                self.reload()
        return self._config

    def force_reload(self):
        """Reload now (admin API writes, SIGHUP). Returns True on success."""
        return self.reload()

    def status(self):
        return {
            "config_loaded": self.config_loaded,
            "reload_count": self.reload_count,
            "last_reload": self.last_reload,
            "last_reload_error": self.last_reload_error,
        }

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _load_initial(self):
        try:
            self._config = Config(config_path=self.config_path())
            self.config_loaded = True
            self.last_reload = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            self._stat_file()
        except Exception as e:
            # Startup failure: there is no last-good config to fall back to,
            # and an empty (all-disabled) config would be allow-all — exactly
            # the fail-open a config typo must not cause. Serve a fail-closed
            # config instead: service stays up, /health reports degraded, and
            # every request is blocked until the config is fixed (hot-reload
            # recovers without a restart).
            logger.critical(f"Initial config load failed: {e} — starting FAIL-CLOSED (all requests blocked) until the config is fixed")
            self._config = _fail_closed_config()
            self.config_loaded = False
            self.last_reload_error = f"initial load failed: {e}"

    def _file_changed(self):
        path = self.config_path()
        try:
            st = os.stat(path)
            mtime, size = st.st_mtime, st.st_size
        except OSError:
            return False
        if self._last_mtime is None:
            self._last_mtime, self._last_size = mtime, size
            # If startup failed (no last-good config), the file appearing IS
            # the recovery event — reload now rather than just recording a
            # baseline and staying fail-closed forever.
            return not self.config_loaded
        if (mtime, size) != (self._last_mtime, self._last_size):
            self._last_mtime, self._last_size = mtime, size
            return True
        # While not loaded (e.g. startup failed on a transient blocklist
        # fetch error), keep retrying — the file didn't change but the
        # failure may have been transient, and staying fail-closed until an
        # operator touches the file breaks the auto-recovery promise. Spaced
        # by RETRY_INTERVAL so a permanently-broken URL doesn't rebuild
        # Config (and hammer the network) on every 2s poll.
        if not self.config_loaded:
            return time.monotonic() - self._last_attempt >= RETRY_INTERVAL
        return False

    def _stat_file(self):
        try:
            st = os.stat(self.config_path())
            self._last_mtime, self._last_size = st.st_mtime, st.st_size
        except OSError:
            self._last_mtime = self._last_size = None

    def rebaseline(self):
        """Re-stat the config file so the poll stops treating its current
        content as a pending change. Used after a failed admin rollback:
        disk holds the rejected change, and without this the next poll sees
        an mtime delta and reloads it with a fresh fetch budget — silently
        applying what the admin was just told to fix manually."""
        self._stat_file()

    def reload(self):
        """
        Build a new Config; on success swap it in atomically and close the
        old one's databases. On failure keep the old config and record the
        error (never fail-open, never crash).
        """
        with self._lock:
            self._last_attempt = time.monotonic()
            try:
                new_config = Config(config_path=self.config_path())
            except Exception as e:
                self.last_reload_error = str(e)
                logger.error(f"Config reload FAILED — keeping last-good config: {e}")
                return False

            self._config = new_config
            self.config_loaded = True
            self.reload_count += 1
            self.last_reload = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            self.last_reload_error = None
            self._stat_file()
            logger.info("Config hot-reloaded successfully")

            # Do NOT close the old config's DB readers: a request thread that
            # grabbed current() before the swap may still be mid-lookup, and
            # reading a closed MMDB raises ValueError which verify_request's
            # catch-all turns into a fail-open 200. Let the old Config (and its
            # readers) be reclaimed by GC once the last reference drops.
            return True


def _fail_closed_config():
    """A valid Config whose rules block everything (IP whitelist mode with an
    empty whitelist short-circuits every request). Used when the real config
    can't be loaded at startup — allow-all would be the fail-open we promise
    never to serve. Built from an in-memory dict so the fallback itself can
    never fail (no temp file, no filesystem dependency). allow_lan/
    allow_unknown are set False here, but ALLOW_LAN/ALLOW_UNKNOWN env vars
    still override settings — the empty IP whitelist is what actually blocks
    everything (it short-circuits before the LAN bypass)."""
    return Config(config_data={
        'settings': {'allow_lan': False, 'allow_unknown': False},
        'ip': {'mode': 'whitelist', 'whitelist': []},
    })
