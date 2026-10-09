"""
Test fixtures for the Config-class architecture.

The service now holds a live Config inside a ConfigManager; tests build
Config objects from temp YAML and exercise verification/admin/health against
them. (The old suite patched flat-module globals that no longer exist.)
"""
import os
import sys

import pytest

# Make `src` importable
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Point DB paths at nonexistent files by default so Config never opens real MMDBs
os.environ.setdefault('COUNTRY_DB_PATH', '/nonexistent/country.mmdb')
os.environ.setdefault('ASN_DB_PATH', '/nonexistent/asn.mmdb')


@pytest.fixture
def write_config(tmp_path):
    """Write a YAML config to a temp file; return its path."""
    def _write(text):
        p = tmp_path / 'config.yaml'
        p.write_text(text)
        return str(p)
    return _write


@pytest.fixture
def make_config(write_config, monkeypatch, tmp_path):
    """Build a Config from a YAML string with env pointed at temp paths."""
    def _make(text):
        path = write_config(text)
        monkeypatch.setenv('CONFIG_PATH', path)
        monkeypatch.setenv('BLOCKLIST_CACHE_DIR', str(tmp_path / 'cache'))
        from src.config import Config
        import src.config as cfgmod
        monkeypatch.setattr(cfgmod, 'CONFIG_PATH', path)
        return Config()
    return _make


@pytest.fixture
def manager(write_config, monkeypatch, tmp_path):
    """Build a ConfigManager rooted at a temp config file."""
    def _make(text):
        path = write_config(text)
        monkeypatch.setenv('CONFIG_PATH', path)
        monkeypatch.setenv('BLOCKLIST_CACHE_DIR', str(tmp_path / 'cache'))
        monkeypatch.setenv('AUDIT_LOG_PATH', str(tmp_path / 'audit.log'))
        from src.manager import ConfigManager
        return ConfigManager(config_path=path, poll_interval=0)
    return _make
