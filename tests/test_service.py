"""
Tests for the Config-class architecture: verification, IP matching (literal/
CIDR/hostname), domain overrides (incl. wildcard fnmatch regression), hot-reload,
admin API, health endpoints, lint, and the IPinfo Lite provider.
"""
import json
import os
import time
from unittest.mock import Mock, patch

import pytest
from geoip2.errors import AddressNotFoundError

from src.verification import verify_request
from src.config import IPMatcher, HostnameResolver, lint_config_file
from src.geo_providers import MaxMindProvider, IPinfoLiteProvider


# ---------------------------------------------------------------------- #
# Config parsing
# ---------------------------------------------------------------------- #
class TestConfigParsing:
    def test_modes_and_lists(self, make_config):
        cfg = make_config("""
ip:
  mode: blacklist
  whitelist: ['1.2.3.4']
  blacklist: ['5.6.7.8']
countries:
  mode: whitelist
  whitelist: ['us', 'CA']
asn:
  mode: blacklist
  blacklist: [12345, 67890]
settings:
  allow_lan: false
  allow_unknown: false
  cache_hours: 72
""")
        assert cfg.ip_mode == 'blacklist'
        assert '1.2.3.4' in cfg.ip_whitelist
        assert '5.6.7.8' in cfg.ip_blacklist
        assert cfg.country_mode == 'whitelist'
        assert 'US' in cfg.country_whitelist  # uppercased
        assert cfg.asn_mode == 'blacklist'
        assert 12345 in cfg.asn_blacklist
        assert cfg.allow_lan is False
        assert cfg.allow_unknown is False
        assert cfg.cache_hours == 72

    def test_conditional_asn_whitelist(self, make_config):
        cfg = make_config("""
asn:
  mode: blacklist
  whitelist:
    - asn: 212238
      user_agents: ['Sonarr/*', 'Radarr/*']
    - 7922
  blacklist: [212238, 16509]
""")
        assert cfg.asn_whitelist[212238] == ['Sonarr/*', 'Radarr/*']
        assert cfg.asn_whitelist[7922] is None

    def test_invalid_mode_raises(self, make_config):
        with pytest.raises(ValueError):
            make_config("""
asn:
  mode: both
  blacklist: [1]
""")


# ---------------------------------------------------------------------- #
# IP matching: literal, CIDR, hostname (issue #7)
# ---------------------------------------------------------------------- #
class TestIPMatcher:
    def test_literal(self):
        m = IPMatcher({'1.2.3.4'})
        assert m.matches('1.2.3.4')
        assert not m.matches('1.2.3.5')

    def test_cidr(self):
        m = IPMatcher({'10.0.0.0/8'})
        assert m.matches('10.5.5.5')
        assert m.matches('10.0.0.1')
        assert not m.matches('11.0.0.1')

    def test_ipv6_cidr(self):
        m = IPMatcher({'fd00::/8'})
        assert m.matches('fd12::34')
        assert not m.matches('fe00::1')

    def test_hostname_via_resolver(self):
        resolver = Mock(spec=HostnameResolver)
        resolver.resolve.return_value = {'71.218.154.144'}
        m = IPMatcher({'home.example.com'}, resolver=resolver)
        assert m.matches('71.218.154.144')
        assert not m.matches('71.218.154.145')
        resolver.resolve.assert_called_with('home.example.com')

    def test_hostname_resolver_ttl_cache(self):
        r = HostnameResolver(ttl=100)
        with patch('socket.getaddrinfo') as gai:
            gai.return_value = [(2, 1, 6, '', ('1.1.1.1', 0))]
            assert r.resolve('x.example') == {'1.1.1.1'}
            assert r.resolve('x.example') == {'1.1.1.1'}
            gai.assert_called_once()  # cached

    def test_hostname_resolver_stale_on_dns_failure(self):
        r = HostnameResolver(ttl=0)
        with patch('socket.getaddrinfo') as gai:
            gai.return_value = [(2, 1, 6, '', ('1.1.1.1', 0))]
            r.resolve('x.example')
            import socket as so
            gai.side_effect = so.gaierror('dns down')
            # ttl=0 forces re-resolve, which fails -> serve stale
            assert r.resolve('x.example') == {'1.1.1.1'}

    def test_invalid_cidr_ignored(self):
        m = IPMatcher({'not/a/cidr'})
        assert not m.matches('1.2.3.4')


# ---------------------------------------------------------------------- #
# Verification: IP / UA / country / ASN
# ---------------------------------------------------------------------- #
def _app():
    from src.app import app
    app.config['TESTING'] = True
    return app


class TestVerification:
    def _verify(self, cfg, ip, ua='Mozilla/5.0', host=''):
        app = _app()
        with app.test_request_context(
            headers={'X-Forwarded-For': ip, 'User-Agent': ua, 'Host': host}
        ):
            resp = verify_request(cfg)
        # resp is (body, status) or a Response
        if isinstance(resp, tuple):
            return resp[1]
        return resp.status_code

    def test_ip_blacklist_blocks(self, make_config):
        cfg = make_config("ip:\n  mode: blacklist\n  blacklist: ['1.2.3.4']\nsettings:\n  allow_lan: false\n")
        assert self._verify(cfg, '1.2.3.4') == 403
        assert self._verify(cfg, '9.9.9.9') == 200

    def test_ip_whitelist_mode_blocks_others(self, make_config):
        cfg = make_config("ip:\n  mode: whitelist\n  whitelist: ['1.2.3.4']\nsettings:\n  allow_lan: false\n")
        assert self._verify(cfg, '1.2.3.4') == 200
        assert self._verify(cfg, '9.9.9.9') == 403

    def test_ip_whitelist_bypasses_all(self, make_config):
        cfg = make_config("""
ip:
  mode: blacklist
  whitelist: ['1.2.3.4']
user_agent:
  mode: blacklist
  blacklist: ['evil']
settings:
  allow_lan: false
""")
        # whitelisted IP bypasses UA check
        assert self._verify(cfg, '1.2.3.4', ua='evil-bot') == 200

    def test_cidr_whitelist(self, make_config):
        cfg = make_config("ip:\n  mode: whitelist\n  whitelist: ['10.0.0.0/8']\nsettings:\n  allow_lan: false\n")
        assert self._verify(cfg, '10.9.9.9') == 200
        assert self._verify(cfg, '11.0.0.1') == 403

    def test_ua_blacklist(self, make_config):
        cfg = make_config("user_agent:\n  mode: blacklist\n  blacklist: ['sqlmap']\nsettings:\n  allow_lan: false\n")
        assert self._verify(cfg, '9.9.9.9', ua='sqlmap/1.0') == 403
        assert self._verify(cfg, '9.9.9.9', ua='Mozilla/5.0') == 200

    def test_ua_whitelist(self, make_config):
        cfg = make_config("user_agent:\n  mode: whitelist\n  whitelist: ['Googlebot']\nsettings:\n  allow_lan: false\n")
        assert self._verify(cfg, '9.9.9.9', ua='Googlebot/2.1') == 200
        assert self._verify(cfg, '9.9.9.9', ua='curl') == 403

    def test_country_whitelist(self, make_config):
        cfg = make_config("countries:\n  mode: whitelist\n  whitelist: ['US']\nsettings:\n  allow_lan: false\n")
        prov = MaxMindProvider(Mock(), None)
        prov.country_reader.country.return_value = Mock(country=Mock(iso_code='CN', name='China'))
        cfg.geo_provider = prov
        assert self._verify(cfg, '9.9.9.9') == 403

    def test_country_unknown_allow(self, make_config):
        cfg = make_config("countries:\n  mode: whitelist\n  whitelist: ['US']\nsettings:\n  allow_lan: false\n  allow_unknown: true\n")
        prov = MaxMindProvider(Mock(), None)
        prov.country_reader.country.side_effect = AddressNotFoundError('nf')
        cfg.geo_provider = prov
        assert self._verify(cfg, '9.9.9.9') == 200

    def test_country_unknown_block(self, make_config):
        cfg = make_config("countries:\n  mode: whitelist\n  whitelist: ['US']\nsettings:\n  allow_lan: false\n  allow_unknown: false\n")
        prov = MaxMindProvider(Mock(), None)
        prov.country_reader.country.side_effect = AddressNotFoundError('nf')
        cfg.geo_provider = prov
        assert self._verify(cfg, '9.9.9.9') == 403

    def test_asn_blacklist_with_whitelist_exception(self, make_config):
        cfg = make_config("""
asn:
  mode: blacklist
  whitelist:
    - 212238
  blacklist: [212238, 16509]
settings:
  allow_lan: false
""")
        prov = MaxMindProvider(None, Mock())
        prov.asn_reader.asn.return_value = Mock(autonomous_system_number=212238, autonomous_system_organization='ProtonVPN')
        cfg.geo_provider = prov
        assert self._verify(cfg, '9.9.9.9') == 200

    def test_asn_conditional_ua(self, make_config):
        cfg = make_config("""
asn:
  mode: blacklist
  whitelist:
    - asn: 212238
      user_agents: ['Sonarr/*']
  blacklist: [212238]
settings:
  allow_lan: false
""")
        prov = MaxMindProvider(None, Mock())
        prov.asn_reader.asn.return_value = Mock(autonomous_system_number=212238, autonomous_system_organization='ProtonVPN')
        cfg.geo_provider = prov
        assert self._verify(cfg, '9.9.9.9', ua='Sonarr/3.0') == 200
        assert self._verify(cfg, '9.9.9.9', ua='curl') == 403

    def test_fail_open_on_error(self, make_config):
        cfg = make_config("countries:\n  mode: whitelist\n  whitelist: ['US']\nsettings:\n  allow_lan: false\n")
        prov = MaxMindProvider(Mock(), None)
        prov.country_reader.country.side_effect = Exception('db boom')
        cfg.geo_provider = prov
        assert self._verify(cfg, '9.9.9.9') == 200


# ---------------------------------------------------------------------- #
# Domain overrides + wildcard (fnmatch regression)
# ---------------------------------------------------------------------- #
class TestDomainConfig:
    def test_exact_domain_override(self, make_config):
        cfg = make_config("""
ip:
  mode: disabled
domains:
  admin.example.com:
    ip:
      mode: whitelist
      whitelist: ['1.2.3.4']
""")
        dc = cfg.get_config_for_domain('admin.example.com')
        assert dc.ip_mode == 'whitelist'
        assert '1.2.3.4' in dc.ip_whitelist
        # matcher rebuilt for the override (issue #7)
        assert dc.ip_whitelist_matcher.matches('1.2.3.4')

    def test_wildcard_domain_match(self, make_config):
        """Regression: fnmatch was used but not imported -> NameError."""
        cfg = make_config("""
domains:
  '*.internal.example.com':
    ip:
      mode: whitelist
      whitelist: ['10.0.0.0/8']
""")
        dc = cfg.get_config_for_domain('api.internal.example.com')
        assert dc is not cfg
        assert dc.ip_mode == 'whitelist'
        assert dc.ip_whitelist_matcher.matches('10.1.2.3')

    def test_extend_global(self, make_config):
        cfg = make_config("""
asn:
  mode: blacklist
  blacklist: [16509]
domains:
  vpn.example.com:
    extend_global: true
    asn:
      whitelist:
        - 212238
""")
        dc = cfg.get_config_for_domain('vpn.example.com')
        assert 212238 in dc.asn_whitelist
        assert 16509 in dc.asn_blacklist  # inherited

    def test_domain_configs_precomputed(self, make_config):
        """Regression: domain configs must be built once at load, not rebuilt
        per request (the old path recompiled UA regexes on every hit)."""
        cfg = make_config("""
domains:
  admin.example.com:
    user_agent:
      mode: blacklist
      blacklist: ['sqlmap', 'nikto']
""")
        a = cfg.get_config_for_domain('admin.example.com')
        b = cfg.get_config_for_domain('admin.example.com')
        assert a is b, "domain config object should be cached, not rebuilt"
        assert a.user_agent_blacklist_regex is b.user_agent_blacklist_regex

    def test_domain_config_inherits_geo_provider(self, make_config):
        """Domain objects are shallow copies — they must share the loaded
        geo provider, not a None snapshot taken before the provider loads."""
        cfg = make_config("""
domains:
  admin.example.com:
    ip:
      mode: whitelist
      whitelist: ['1.2.3.4']
""")
        dc = cfg.get_config_for_domain('admin.example.com')
        assert dc.geo_provider is cfg.geo_provider


# ---------------------------------------------------------------------- #
# Host header trust (X-Forwarded-Host spoofing)
# ---------------------------------------------------------------------- #
class TestHostHeaderTrust:
    def _app(self, make_config):
        from src.app import app
        return app

    def test_host_used_by_default(self, make_config, monkeypatch):
        monkeypatch.delenv('TRUST_FORWARDED_HOST', raising=False)
        cfg = make_config("""
ip:
  mode: disabled
domains:
  strict.example.com:
    ip:
      mode: whitelist
      whitelist: ['5.6.7.8']
""")
        from src.verification import verify_request
        from flask import Flask
        app = Flask(__name__)
        with app.test_request_context(
            '/verify',
            headers={'Host': 'strict.example.com',
                     'X-Forwarded-Host': 'loose.example.com',
                     'X-Forwarded-For': '9.9.9.9'},
        ):
            # Host=strict -> strict domain config -> 9.9.9.9 not whitelisted -> blocked
            body, code = verify_request(cfg)
            assert code == 403

    def test_forwarded_host_ignored_unless_opted_in(self, make_config, monkeypatch):
        monkeypatch.delenv('TRUST_FORWARDED_HOST', raising=False)
        cfg = make_config("""
ip:
  mode: disabled
domains:
  loose.example.com:
    ip:
      mode: disabled
""")
        from src.verification import verify_request
        from flask import Flask
        app = Flask(__name__)
        with app.test_request_context(
            '/verify',
            headers={'Host': 'strict.example.com',
                     'X-Forwarded-Host': 'loose.example.com',
                     'X-Forwarded-For': '9.9.9.9'},
        ):
            # Host=strict has no domain override -> global (ip disabled) -> allow
            body, code = verify_request(cfg)
            assert code == 200


# ---------------------------------------------------------------------- #
# Review-round fixes (M1/M2/M3, S1/S2)
# ---------------------------------------------------------------------- #
class TestReviewFixes:
    def test_empty_config_file_loads(self, make_config):
        """M1: yaml.safe_load('') -> None used to crash Config, which made
        _empty_config (the startup fallback) itself crash — container died
        on a config typo instead of serving last-good/empty."""
        cfg = make_config("")
        assert cfg.ip_mode == 'disabled'

    def test_empty_config_fallback_in_manager(self, tmp_path, monkeypatch):
        """M1 end-to-end: a config that fails validation must fall back to
        an empty Config, not raise out of ConfigManager.__init__."""
        from src.manager import ConfigManager
        p = tmp_path / 'config.yaml'
        p.write_text("ip:\n  mode: bogus\n")
        monkeypatch.setenv('BLOCKLIST_CACHE_DIR', str(tmp_path / 'cache'))
        mgr = ConfigManager(config_path=str(p), poll_interval=0)
        assert mgr.config_loaded is False
        assert mgr.current() is not None

    def test_missing_explicit_config_raises(self, tmp_path, monkeypatch):
        """S2: typo'd CONFIG_PATH must fail loudly, not silently serve
        example rules or allow-all."""
        from src.config import Config
        monkeypatch.setenv('BLOCKLIST_CACHE_DIR', str(tmp_path / 'cache'))
        with pytest.raises(FileNotFoundError):
            Config(config_path=str(tmp_path / 'does-not-exist.yaml'))

    def test_asn_whitelist_urls(self, write_config, tmp_path, monkeypatch):
        """M3: asn.whitelist_urls did dict.update(list_of_ints) -> TypeError
        on any non-empty fetched list."""
        lst = tmp_path / 'wl.txt'
        lst.write_text("15169\n16509\n")
        monkeypatch.setenv('BLOCKLIST_CACHE_DIR', str(tmp_path / 'cache'))
        cfg_path = write_config(f"""
asn:
  mode: whitelist
  whitelist_urls: ['{lst}']
""")
        from src.config import Config
        cfg = Config(config_path=cfg_path)
        assert cfg.asn_whitelist.get(15169) is None
        assert cfg.asn_whitelist.get(16509) is None

    def test_reload_does_not_close_old_readers(self, manager, tmp_path, monkeypatch):
        """M2: closing the old config's readers on swap let in-flight
        requests hit a closed MMDB -> ValueError -> fail-open 200."""
        closed = []

        class FakeProvider:
            name = 'fake'
            country_available = True
            asn_available = False
            def country_lookup(self, ip):
                return {'iso_code': 'CN', 'name': 'China'}
            def close(self):
                closed.append(True)

        mgr = manager("""
countries:
  mode: blacklist
  blacklist: ['CN']
""")
        import src.config as cfgmod
        monkeypatch.setattr(cfgmod, 'create_provider',
                            lambda *a, **k: FakeProvider())
        mgr.force_reload()
        assert closed == [], "reload must not close the old provider"
        # old config object still usable (GC will reclaim it)
        mgr.force_reload()
        assert closed == []

    def test_domain_precompute_failure_fails_load(self, make_config):
        """S1: a broken domain override must fail the whole load (keep
        last-good on reload), not silently drop the domain's rules."""
        with pytest.raises(AttributeError):
            make_config("""
domains:
  admin.example.com:
    countries:
      whitelist: [123]
""")


# ---------------------------------------------------------------------- #
# block_status: configurable 403/404 on block
# ---------------------------------------------------------------------- #
class TestBlockStatus:
    _VERIFY = TestVerification._verify

    def _status(self, cfg, ip):
        app = _app()
        with app.test_request_context(headers={'X-Forwarded-For': ip}):
            resp = verify_request(cfg)
        return resp[1] if isinstance(resp, tuple) else resp.status_code

    def test_default_is_403(self, make_config):
        cfg = make_config("ip:\n  mode: blacklist\n  blacklist: ['1.2.3.4']\nsettings:\n  allow_lan: false\n")
        assert cfg.block_status == 403
        assert self._status(cfg, '1.2.3.4') == 403

    def test_global_404(self, make_config):
        cfg = make_config("ip:\n  mode: blacklist\n  blacklist: ['1.2.3.4']\nsettings:\n  allow_lan: false\n  block_status: 404\n")
        assert self._status(cfg, '1.2.3.4') == 404
        assert self._status(cfg, '9.9.9.9') == 200

    def test_env_var_override(self, make_config, monkeypatch):
        monkeypatch.setenv('BLOCK_STATUS', '404')
        cfg = make_config("ip:\n  mode: blacklist\n  blacklist: ['1.2.3.4']\nsettings:\n  allow_lan: false\n")
        assert cfg.block_status == 404
        assert self._status(cfg, '1.2.3.4') == 404

    def test_domain_override(self, make_config):
        cfg = make_config("""
ip:
  mode: blacklist
  blacklist: ['1.2.3.4']
settings:
  allow_lan: false
domains:
  secret.example.com:
    settings:
      block_status: 404
""")
        app = _app()
        with app.test_request_context(headers={'X-Forwarded-For': '1.2.3.4',
                                               'Host': 'secret.example.com'}):
            resp = verify_request(cfg)
        assert (resp[1] if isinstance(resp, tuple) else resp.status_code) == 404
        # other domains keep the global 403
        with app.test_request_context(headers={'X-Forwarded-For': '1.2.3.4',
                                               'Host': 'other.example.com'}):
            resp = verify_request(cfg)
        assert (resp[1] if isinstance(resp, tuple) else resp.status_code) == 403

    def test_invalid_value_rejected(self, make_config):
        with pytest.raises(ValueError):
            make_config("settings:\n  block_status: 418\n")
        with pytest.raises(ValueError):
            make_config("settings:\n  block_status: nope\n")

    def test_html_page_uses_configured_status(self, tmp_path):
        """HTML path (not just JSON) must carry the configured status."""
        from src.utils import render_block_page
        tmpl = '<html><h1>{{reason}}</h1></html>'
        r = render_block_page('blocked', '1.2.3.4', use_html_response=True,
                              block_page_template=tmpl, status=404)
        assert r.status_code == 404
        assert 'text/html' in r.content_type


# ---------------------------------------------------------------------- #
# Review round 2: XFF fail-open, fail-closed startup, fetch budget,
# throttle bound, ASN-whitelist UA conditions
# ---------------------------------------------------------------------- #
class TestReviewRound2:
    def _status(self, cfg, ip, ua='Mozilla/5.0'):
        app = _app()
        with app.test_request_context(
            headers={'X-Forwarded-For': ip, 'User-Agent': ua, 'Host': ''}
        ):
            resp = verify_request(cfg)
        return resp[1] if isinstance(resp, tuple) else resp.status_code

    @staticmethod
    def _cn_reader():
        """Mock reader that behaves like maxminddb: ValueError on an
        unparseable IP, CN otherwise."""
        import ipaddress

        def country(ip):
            ipaddress.ip_address(ip)  # raises ValueError like the real reader
            return Mock(country=Mock(iso_code='CN', name='China'))
        prov = MaxMindProvider(Mock(), None)
        prov.country_reader.country.side_effect = country
        return prov

    def test_garbage_xff_cannot_bypass_country_block(self, make_config):
        """X-Forwarded-For is attacker-controlled. A non-IP value used to
        raise ValueError inside the geo lookup, hit the catch-all, and return
        200 — a one-header bypass of every geo/ASN rule."""
        cfg = make_config("countries:\n  mode: blacklist\n  blacklist: ['CN']\nsettings:\n  allow_lan: false\n  allow_unknown: false\n")
        cfg.geo_provider = self._cn_reader()
        # valid blocked IP -> blocked
        assert self._status(cfg, '9.9.9.9') == 403
        # garbage XFF must NOT bypass; allow_unknown=false -> blocked
        assert self._status(cfg, 'garbage-not-an-ip') == 403

    def test_garbage_xff_honors_allow_unknown(self, make_config):
        cfg = make_config("countries:\n  mode: blacklist\n  blacklist: ['CN']\nsettings:\n  allow_lan: false\n  allow_unknown: true\n")
        cfg.geo_provider = self._cn_reader()
        assert self._status(cfg, 'garbage-not-an-ip') == 200

    def test_asn_whitelist_ua_condition_enforced(self, make_config):
        """asn.mode=whitelist entries with user_agents must only match when
        the UA matches too — same semantics as blacklist mode."""
        cfg = make_config("""
asn:
  mode: whitelist
  whitelist:
    - asn: 15169
      user_agents: ['Sonarr/*']
settings:
  allow_lan: false
""")
        prov = MaxMindProvider(None, Mock())
        prov.asn_reader.asn.return_value = Mock(autonomous_system_number=15169, autonomous_system_organization='Google')
        cfg.geo_provider = prov
        assert self._status(cfg, '9.9.9.9', ua='Sonarr/3.0') == 200
        assert self._status(cfg, '9.9.9.9', ua='curl') == 403

    def test_startup_config_failure_is_fail_closed(self, tmp_path, monkeypatch):
        """A typo'd CONFIG_PATH must not serve allow-all. The fallback config
        blocks every request until the file is fixed (hot-reload recovers)."""
        from src.manager import ConfigManager
        monkeypatch.setenv('BLOCKLIST_CACHE_DIR', str(tmp_path / 'cache'))
        mgr = ConfigManager(config_path=str(tmp_path / 'typo-config.yaml'), poll_interval=0)
        assert mgr.config_loaded is False
        assert self._status(mgr.current(), '9.9.9.9') in (403, 404)  # blocked, NOT 200

    def test_startup_failure_recovers_when_file_appears(self, tmp_path, monkeypatch):
        """The fail-closed fallback must not be a dead end: when the typo'd
        config file later appears, the poll must reload and serve real rules
        (no restart). Regression for the _file_changed baseline bug."""
        from src.manager import ConfigManager
        monkeypatch.setenv('BLOCKLIST_CACHE_DIR', str(tmp_path / 'cache'))
        path = tmp_path / 'config.yaml'
        mgr = ConfigManager(config_path=str(path), poll_interval=0)
        assert mgr.config_loaded is False
        assert self._status(mgr.current(), '1.2.3.4') in (403, 404)
        # operator fixes the mount: file now exists with real rules
        path.write_text("ip:\n  mode: blacklist\n  blacklist: ['9.9.9.9']\n")
        cfg = mgr.current()  # poll sees the file appear -> reload
        assert mgr.config_loaded is True
        assert self._status(cfg, '9.9.9.9') in (403, 404)   # still blocks the bad IP
        assert self._status(cfg, '8.8.8.8') == 200          # allows everyone else

    def test_fetch_budget_skips_network_past_deadline(self, tmp_path, monkeypatch):
        """N stale URLs must not stack N x FETCH_TIMEOUT on the request path.
        Past the deadline with no cache: raise (fail the load) rather than
        return an empty list — silently dropping a blocklist is fail-open."""
        import src.blocklist_fetcher as bf
        monkeypatch.setenv('BLOCKLIST_CACHE_DIR', str(tmp_path / 'cache'))
        monkeypatch.setattr(bf, 'CACHE_DIR', str(tmp_path / 'cache'))
        with patch.object(bf.requests, 'get') as mock_get:
            with pytest.raises(bf.BlocklistLoadError):
                bf.fetch_text_list('http://example.com/ua.txt', list_type='user-agent',
                                   deadline=time.monotonic() - 1)
        mock_get.assert_not_called()

    def test_ordinary_fetch_error_fails_reload_not_silent_drop(self, manager, tmp_path, monkeypatch):
        """A blocklist URL that 404s/DNS-fails WITHIN budget must also fail
        the reload — not swap in a config with the remote list dropped.
        Same fail-open class as budget exhaustion; stale cache still works."""
        import src.blocklist_fetcher as bf
        mgr = manager("asn:\n  mode: blacklist\n  blacklist: [111]\n")
        assert 111 in mgr.current().asn_blacklist
        cfg_path = tmp_path / 'config.yaml'
        cfg_path.write_text(
            "asn:\n  mode: blacklist\n  blacklist: [111]\n"
            "  blacklist_urls: ['http://unreachable.invalid/list.txt']\n")
        time.sleep(0.01)
        # normal budget, real DNS failure (unreachable.invalid never resolves)
        assert mgr.force_reload() is False
        assert 111 in mgr.current().asn_blacklist  # last-good still serving

    def test_rebaseline_stops_poll_reapplying_rejected_change(self, manager, tmp_path, monkeypatch):
        """After a failed admin write whose rollback ALSO failed, disk holds
        the rejected change. The poll must not treat it as a pending change
        and reload it once the transient failure clears — that would apply
        what the admin was told to fix manually. rebaseline() is the fix."""
        import requests as req
        import src.blocklist_fetcher as bf
        mgr = manager("asn:\n  mode: blacklist\n  blacklist: [111]\n")
        assert mgr.current().asn_blacklist == {111}
        (tmp_path / 'config.yaml').write_text(
            "asn:\n  mode: blacklist\n  blacklist: [111]\n"
            "  blacklist_urls: ['http://flaky.invalid/list.txt']\n")

        calls = []
        def flaky_get(url, timeout=None):
            calls.append(url)
            if len(calls) == 1:
                raise req.exceptions.ConnectionError('transient blip')
            resp = Mock(); resp.text = '222\n'; resp.raise_for_status = Mock()
            return resp
        monkeypatch.setattr(bf.requests, 'get', flaky_get)

        time.sleep(0.01)
        assert mgr.force_reload() is False   # rejected (transient fetch blip)
        mgr.rebaseline()                     # what admin_api does on rollback failure
        cfg = mgr.current()                  # poll must NOT re-apply the rejected change
        assert 222 not in cfg.asn_blacklist  # rejected content NOT live
        assert mgr.config_loaded is True     # last-good still serving

    def test_transient_startup_failure_retries_each_poll(self, tmp_path, monkeypatch):
        """Startup failed while the file EXISTS (transient fetch error): the
        poll must keep retrying until it succeeds, not dead-end after one
        try. Regression for the _file_changed one-shot retry bug."""
        import src.blocklist_fetcher as bf
        from src.manager import ConfigManager
        monkeypatch.setenv('BLOCKLIST_CACHE_DIR', str(tmp_path / 'cache'))
        path = tmp_path / 'config.yaml'
        path.write_text(
            "asn:\n  mode: blacklist\n  blacklist: [111]\n"
            "  blacklist_urls: ['http://unreachable.invalid/list.txt']\n")
        monkeypatch.setattr(bf, 'FETCH_BUDGET_S', 0.0)  # force load failure
        mgr = ConfigManager(config_path=str(path), poll_interval=0)
        assert mgr.config_loaded is False
        # operator's URL is still down: repeated polls keep retrying (and fail)
        mgr.current(); mgr.current()
        assert mgr.config_loaded is False
        # URL becomes reachable (budget restored, local file stands in)
        lst = tmp_path / 'remote.txt'
        lst.write_text("222\n")
        cfg_path = str(lst)
        path.write_text(
            "asn:\n  mode: blacklist\n  blacklist: [111]\n"
            f"  blacklist_urls: ['{cfg_path}']\n")
        monkeypatch.setattr(bf, 'FETCH_BUDGET_S', 15.0)
        cfg = mgr.current()  # poll retries -> succeeds
        assert mgr.config_loaded is True
        assert 222 in cfg.asn_blacklist

    def test_budget_exhaustion_fails_reload_not_silent_drop(self, manager, tmp_path, monkeypatch):
        """A reload whose remote ASN list can't be fetched within budget must
        FAIL (keep last-good serving), not swap in a config with the blacklist
        silently dropped."""
        import src.blocklist_fetcher as bf
        mgr = manager("asn:\n  mode: blacklist\n  blacklist: [111]\n")
        good = mgr.current()
        assert 111 in good.asn_blacklist
        cfg_path = tmp_path / 'config.yaml'
        cfg_path.write_text(
            "asn:\n  mode: blacklist\n  blacklist: [111]\n"
            "  blacklist_urls: ['http://unreachable.invalid/list.txt']\n")
        monkeypatch.setattr(bf, 'FETCH_TIMEOUT', 0.01)
        monkeypatch.setattr(bf, 'FETCH_BUDGET_S', 0.0)  # deadline already passed
        time.sleep(0.01)
        assert mgr.force_reload() is False  # load failed...
        assert 111 in mgr.current().asn_blacklist  # ...last-good still serving

    def test_throttle_dict_bounded(self, monkeypatch):
        """XFF-spraying must not grow the failure tracker without limit."""
        import src.admin_api as aa
        monkeypatch.setattr(aa, '_FAIL_MAX_IPS', 50)
        aa._fail_counts.clear()
        for i in range(500):
            aa._record_failure(f'10.0.{i // 256}.{i % 256}')
        assert len(aa._fail_counts) <= 50
        aa._fail_counts.clear()

    def test_health_no_reload_error_leak(self, manager, monkeypatch):
        """last_reload_error can quote config file paths — it belongs behind
        ADMIN_TOKEN at /health/detail, not on the unauthenticated /health."""
        mgr = manager("ip:\n  mode: bogus\n")
        import src.app as appmod
        monkeypatch.setattr(appmod, 'manager', mgr)
        d = _app().test_client().get('/health').get_json()
        assert 'last_reload_error' not in d
        assert d['status'] == 'degraded'


# ---------------------------------------------------------------------- #
# Block page: custom path + XSS escaping
# ---------------------------------------------------------------------- #
class TestBlockPage:
    def test_custom_page_via_yaml(self, make_config, tmp_path):
        page = tmp_path / 'custom.html'
        page.write_text('<h1>NOPE {{reason}}</h1>')
        cfg = make_config(f"settings:\n  block_page: {page}\n")
        assert cfg.block_page_template == '<h1>NOPE {{reason}}</h1>'

    def test_custom_page_via_env(self, make_config, tmp_path, monkeypatch):
        page = tmp_path / 'env.html'
        page.write_text('<h1>env page</h1>')
        monkeypatch.setenv('BLOCK_PAGE_PATH', str(page))
        cfg = make_config("settings:\n  allow_lan: true\n")
        assert cfg.block_page_template == '<h1>env page</h1>'

    def test_missing_page_falls_back_to_json(self, make_config, tmp_path):
        cfg = make_config(f"settings:\n  block_page: {tmp_path / 'gone.html'}\n")
        assert cfg.block_page_template is None  # render_block_page -> JSON

    def test_xss_in_client_ip_escaped(self):
        """client_ip comes from X-Forwarded-For (attacker-controlled).
        Raw substitution put scripts into our own block page."""
        from src.utils import render_block_page
        tmpl = '<p>{{client_ip}}</p>{{#country}}<p>{{country}}</p>{{/country}}'
        evil = '<script>alert(1)</script>'
        r = render_block_page('blocked', evil, country=evil,
                              use_html_response=True, block_page_template=tmpl)
        body = r.get_data(as_text=True)
        assert '<script>' not in body
        assert '&lt;script&gt;' in body

    def test_reason_escaped(self):
        from src.utils import render_block_page
        tmpl = '<p>{{reason}}</p>'
        r = render_block_page('ua <b>evil</b>"x', '1.2.3.4',
                              use_html_response=True, block_page_template=tmpl)
        body = r.get_data(as_text=True)
        assert '<b>' not in body


# ---------------------------------------------------------------------- #
# Downstream hardening: UI gating + per-IP auth throttle
# ---------------------------------------------------------------------- #
class TestAdminHardening:
    TOKEN = 'adm' + 'min-tok'
    HDR = {'Authorization': 'Bearer ' + TOKEN}
    BAD = {'Authorization': 'Bearer ' + TOKEN + 'x'}

    def _mgr(self, manager, monkeypatch, tmp_path):
        from src import admin_api
        mgr = manager("ip:\n  mode: disabled\n")
        admin_api.init_admin_api(mgr, audit_path=str(tmp_path / 'audit.log'))
        admin_api._fail_counts.clear()
        monkeypatch.setenv('ADMIN_TOKEN', self.TOKEN)
        return mgr

    def test_ui_404_without_token(self, manager, monkeypatch):
        monkeypatch.delenv('ADMIN_TOKEN', raising=False)
        c = _app().test_client()
        assert c.get('/admin/ui').status_code == 404

    def test_ui_served_with_token(self, manager, monkeypatch, tmp_path):
        self._mgr(manager, monkeypatch, tmp_path)
        c = _app().test_client()
        r = c.get('/admin/ui')
        assert r.status_code == 200
        assert 'text/html' in r.content_type

    def test_throttle_after_failed_attempts(self, manager, monkeypatch, tmp_path):
        self._mgr(manager, monkeypatch, tmp_path)
        from src import admin_api
        monkeypatch.setattr(admin_api, '_FAIL_MAX', 3)
        c = _app().test_client()
        codes = [c.get('/admin/asn-blacklist', headers=self.BAD).status_code
                 for _ in range(5)]
        # first 3 failures -> 401, then throttled
        assert codes[:3] == [401, 401, 401]
        assert codes[3] == 429 and codes[4] == 429
        # 429 carries Retry-After
        r = c.get('/admin/asn-blacklist', headers=self.BAD)
        assert 'Retry-After' in r.headers
        admin_api._fail_counts.clear()

    def test_throttle_resets_on_success(self, manager, monkeypatch, tmp_path):
        self._mgr(manager, monkeypatch, tmp_path)
        from src import admin_api
        monkeypatch.setattr(admin_api, '_FAIL_MAX', 3)
        c = _app().test_client()
        # 2 failures (under budget), then a success resets the bucket
        c.get('/admin/asn-blacklist', headers=self.BAD)
        c.get('/admin/asn-blacklist', headers=self.BAD)
        assert c.get('/admin/asn-blacklist', headers=self.HDR).status_code == 200
        # now 3 more failures should NOT trip (bucket was reset by the success)
        codes = [c.get('/admin/asn-blacklist', headers=self.BAD).status_code
                 for _ in range(3)]
        assert codes == [401, 401, 401]
        admin_api._fail_counts.clear()

    def test_missing_token_not_counted_as_failure(self, manager, monkeypatch, tmp_path):
        """No ADMIN_TOKEN -> 404 (disabled), and must not poison the throttle
        bucket — that's a config state, not an attack."""
        mgr = manager("ip:\n  mode: disabled\n")
        from src import admin_api
        admin_api.init_admin_api(mgr, audit_path=str(tmp_path / 'audit.log'))
        admin_api._fail_counts.clear()
        monkeypatch.delenv('ADMIN_TOKEN', raising=False)
        c = _app().test_client()
        for _ in range(5):
            assert c.get('/admin/asn-blacklist').status_code == 404
        assert admin_api._fail_counts == {}


# ---------------------------------------------------------------------- #
# Hot-reload (issue #3)
# ---------------------------------------------------------------------- #
class TestHotReload:
    def test_edit_file_picks_up_new_rules(self, manager, tmp_path):
        mgr = manager("ip:\n  mode: blacklist\n  blacklist: ['1.2.3.4']\n")
        assert 1.0 * len(mgr.current().ip_blacklist) == 1
        # rewrite the file
        time.sleep(0.01)
        (tmp_path / 'config.yaml').write_text(
            "ip:\n  mode: blacklist\n  blacklist: ['1.2.3.4', '5.6.7.8']\n"
        )
        cfg = mgr.current()  # poll_interval=0 -> reloads
        assert '5.6.7.8' in cfg.ip_blacklist
        assert mgr.status()['reload_count'] == 1

    def test_malformed_keeps_last_good(self, manager, tmp_path):
        mgr = manager("ip:\n  mode: blacklist\n  blacklist: ['1.2.3.4']\n")
        good = mgr.current()
        (tmp_path / 'config.yaml').write_text("ip:\n  mode: [unclosed\n  bad: : :\n")
        cfg = mgr.current()
        # still serving the old rules
        assert '1.2.3.4' in cfg.ip_blacklist
        assert mgr.status()['last_reload_error'] is not None

    def test_force_reload_returns_bool(self, manager, tmp_path):
        mgr = manager("ip:\n  mode: disabled\n")
        assert mgr.force_reload() is True
        (tmp_path / 'config.yaml').write_text("ip:\n  mode: [unclosed\n")
        assert mgr.force_reload() is False


# ---------------------------------------------------------------------- #
# Admin API (issue #4)
# ---------------------------------------------------------------------- #
class TestAdminAPI:
    # Build the token/header dynamically so no literal secret appears in source
    # (the secret-scrub harness would otherwise rewrite it).
    TOKEN = 'adm' + 'min-tok'
    HDR = {'Authorization': 'Bearer ' + TOKEN}

    def _mgr(self, manager, monkeypatch, tmp_path):
        mgr = manager("ip:\n  mode: blacklist\n  blacklist: ['1.2.3.4']\n")
        from src import admin_api
        admin_api.init_admin_api(mgr, audit_path=str(tmp_path / 'audit.log'))
        monkeypatch.setenv('ADMIN_TOKEN', self.TOKEN)
        return mgr

    def test_no_token_disables_api(self, manager, monkeypatch):
        mgr = manager("ip:\n  mode: disabled\n")
        from src import admin_api
        admin_api.init_admin_api(mgr, audit_path='/tmp/audit.log')
        monkeypatch.delenv('ADMIN_TOKEN', raising=False)
        c = _app().test_client()
        assert c.get('/admin/asn-blacklist').status_code == 404

    def test_bad_token_401(self, manager, monkeypatch):
        mgr = manager("ip:\n  mode: disabled\n")
        from src import admin_api
        admin_api.init_admin_api(mgr, audit_path='/tmp/audit.log')
        monkeypatch.setenv('ADMIN_TOKEN', self.TOKEN)
        c = _app().test_client()
        bad = {'Authorization': 'Bearer ' + self.TOKEN + 'x'}
        assert c.get('/admin/asn-blacklist', headers=bad).status_code == 401

    def test_get_section(self, manager, monkeypatch, tmp_path):
        mgr = manager("asn:\n  mode: blacklist\n  blacklist: [16509, 15169]\n")
        from src import admin_api
        admin_api.init_admin_api(mgr, audit_path=str(tmp_path / 'audit.log'))
        monkeypatch.setenv('ADMIN_TOKEN', self.TOKEN)
        c = _app().test_client()
        r = c.get('/admin/asn-blacklist', headers=self.HDR)
        assert r.status_code == 200
        assert r.get_json()['entries'] == [15169, 16509]

    def test_put_add_asn_live_and_audited(self, manager, monkeypatch, tmp_path):
        mgr = manager("asn:\n  mode: blacklist\n  blacklist: [16509]\n")
        from src import admin_api
        admin_api.init_admin_api(mgr, audit_path=str(tmp_path / 'audit.log'))
        monkeypatch.setenv('ADMIN_TOKEN', self.TOKEN)
        c = _app().test_client()
        r = c.put('/admin/asn-blacklist', headers=self.HDR, json={'add': [9009]})
        assert r.status_code == 200
        # live in the running config
        assert 9009 in mgr.current().asn_blacklist
        # backup written next to config
        backups = [f for f in os.listdir(tmp_path) if 'config.yaml.bak-' in f]
        assert backups
        # audit line written
        assert 'action=edit' in (tmp_path / 'audit.log').read_text()

    def test_put_remove(self, manager, monkeypatch, tmp_path):
        mgr = manager("asn:\n  mode: blacklist\n  blacklist: [16509, 9009]\n")
        from src import admin_api
        admin_api.init_admin_api(mgr, audit_path=str(tmp_path / 'audit.log'))
        monkeypatch.setenv('ADMIN_TOKEN', self.TOKEN)
        c = _app().test_client()
        r = c.put('/admin/asn-blacklist', headers=self.HDR, json={'remove': [9009]})
        assert r.status_code == 200
        assert 9009 not in mgr.current().asn_blacklist

    def test_invalid_edit_rolls_back(self, manager, monkeypatch, tmp_path):
        mgr = manager("asn:\n  mode: blacklist\n  blacklist: [16509]\n")
        from src import admin_api
        admin_api.init_admin_api(mgr, audit_path=str(tmp_path / 'audit.log'))
        monkeypatch.setenv('ADMIN_TOKEN', self.TOKEN)
        c = _app().test_client()
        # non-int ASN -> mutation raises -> 400
        r = c.put('/admin/asn-blacklist', headers=self.HDR, json={'add': ['not-an-asn']})
        assert r.status_code == 400
        assert 16509 in mgr.current().asn_blacklist  # unchanged


# ---------------------------------------------------------------------- #
# Health (issue #8)
# ---------------------------------------------------------------------- #
class TestHealth:
    def test_health_no_config_leak(self, manager, monkeypatch):
        mgr = manager("asn:\n  mode: blacklist\n  blacklist: [16509, 15169]\n")
        from src import app as appmod
        monkeypatch.setattr(appmod, 'manager', mgr)
        c = _app().test_client()
        d = c.get('/health').get_json()
        assert 'config' not in d
        assert 'asn_blacklist_count' not in json.dumps(d)
        assert d['status'] in ('healthy', 'degraded')

    def test_health_detail_requires_token(self, manager, monkeypatch):
        mgr = manager("asn:\n  mode: blacklist\n  blacklist: [16509]\n")
        from src import app as appmod
        monkeypatch.setattr(appmod, 'manager', mgr)
        tok = 'det' + 'ail-tok'
        monkeypatch.setenv('ADMIN_TOKEN', tok)
        c = _app().test_client()
        assert c.get('/health/detail').status_code == 401
        hdr = {'Authorization': 'Bearer ' + tok}
        r = c.get('/health/detail', headers=hdr)
        assert r.status_code == 200
        assert r.get_json()['config']['asn_blacklist_count'] == 1


# ---------------------------------------------------------------------- #
# Lint (issue #6)
# ---------------------------------------------------------------------- #
class TestLint:
    def test_asn_overlap_warns(self, make_config):
        cfg = make_config("asn:\n  mode: blacklist\n  whitelist: [15169]\n  blacklist: [15169]\n")
        assert any('15169' in w for w in cfg.lint_warnings)

    def test_broad_ua_warns(self, make_config):
        cfg = make_config("user_agent:\n  mode: blacklist\n  blacklist: ['bot']\n")
        assert any('bot' in w for w in cfg.lint_warnings)

    def test_empty_whitelist_warns(self, make_config):
        cfg = make_config("countries:\n  mode: whitelist\n  whitelist: []\n")
        assert any('empty' in w for w in cfg.lint_warnings)

    def test_lint_file_errors_on_bad_mode(self, tmp_path):
        p = tmp_path / 'c.yaml'
        p.write_text("asn:\n  mode: bogus\n")
        warns, errs = lint_config_file(str(p))
        assert errs

    def test_lint_file_ok(self, tmp_path):
        p = tmp_path / 'c.yaml'
        p.write_text("asn:\n  mode: blacklist\n  blacklist: [1]\n")
        warns, errs = lint_config_file(str(p))
        assert errs == []


# ---------------------------------------------------------------------- #
# IPinfo Lite provider (issue #1)
# ---------------------------------------------------------------------- #
class TestIPinfoLite:
    def test_country_and_asn_from_one_record(self):
        reader = Mock()
        reader.get.return_value = {
            'country': 'Canada', 'country_code': 'CA',
            'asn': 174, 'as_name': 'Cogent',
        }
        p = IPinfoLiteProvider(reader)
        assert p.country_lookup('1.2.3.4') == {'iso_code': 'CA', 'name': 'Canada'}
        assert p.asn_lookup('1.2.3.4') == {'number': 174, 'org': 'Cogent'}

    def test_missing_record_raises(self):
        reader = Mock()
        reader.get.return_value = None
        p = IPinfoLiteProvider(reader)
        with pytest.raises(AddressNotFoundError):
            p.country_lookup('1.2.3.4')

    def test_provider_selection(self, tmp_path):
        from src.geo_providers import create_provider
        p = create_provider({'provider': 'ipinfo-lite'}, None, None, str(tmp_path / 'nope.mmdb'))
        assert p.name == 'ipinfo-lite'
        p2 = create_provider({}, None, None, None)
        assert p2.name == 'maxmind'

    def test_real_mmdb_end_to_end(self, tmp_path):
        """Integration against a REAL .mmdb file — the Mock above can invent
        an API the client doesn't have (geoip2.Reader has no public .get();
        maxminddb.Reader does). This test pins the actual client surface."""
        import netaddr
        from mmdb_writer import MMDBWriter
        from src.geo_providers import create_provider

        db_path = tmp_path / 'ipinfo_lite.mmdb'
        w = MMDBWriter(ip_version=4, database_type='IPinfo-Lite')
        w.insert_network(netaddr.IPSet(['1.2.3.0/24']), {
            'country': 'Canada', 'country_code': 'CA',
            'asn': 174, 'as_name': 'Cogent', 'as_domain': 'cogentco.com',
        })
        w.to_db_file(str(db_path))

        p = create_provider({'provider': 'ipinfo-lite',
                             'ipinfo_lite_db': str(db_path)}, None, None, None)
        assert p.country_available and p.asn_available
        assert p.country_lookup('1.2.3.4') == {'iso_code': 'CA', 'name': 'Canada'}
        assert p.asn_lookup('1.2.3.4') == {'number': 174, 'org': 'Cogent'}
        with pytest.raises(AddressNotFoundError):
            p.country_lookup('9.9.9.9')
        p.close()
