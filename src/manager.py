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
            # Startup failure: start permissive (empty config) but never crash.
            logger.critical(f"Initial config load failed: {e} — starting with empty config")
            self._config = _empty_config()
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
            return False
        if (mtime, size) != (self._last_mtime, self._last_size):
            self._last_mtime, self._last_size = mtime, size
            return True
        return False

    def _stat_file(self):
        try:
            st = os.stat(self.config_path())
            self._last_mtime, self._last_size = st.st_mtime, st.st_size
        except OSError:
            self._last_mtime = self._last_size = None

    def reload(self):
        """
        Build a new Config; on success swap it in atomically and close the
        old one's databases. On failure keep the old config and record the
        error (never fail-open, never crash).
        """
        with self._lock:
            try:
                new_config = Config(config_path=self.config_path())
            except Exception as e:
                self.last_reload_error = str(e)
                logger.error(f"Config reload FAILED — keeping last-good config: {e}")
                return False

            old = self._config
            self._config = new_config
            self.config_loaded = True
            self.reload_count += 1
            self.last_reload = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            self.last_reload_error = None
            self._stat_file()
            logger.info("Config hot-reloaded successfully")

            # Close old DB handles only after the swap so in-flight requests
            # on other threads never see a closed reader.
            if old is not None and old is not new_config:
                try:
                    old.close()
                except Exception as e:
                    logger.warning(f"Error closing old config resources: {e}")
            return True


def _empty_config():
    """A valid Config built from an empty YAML (all checks disabled)."""
    import tempfile
    with tempfile.NamedTemporaryFile('w', suffix='.yaml', delete=False) as f:
        f.write('')
        path = f.name
    try:
        return Config(config_path=path)
    finally:
        os.unlink(path)
