"""
Configuration management for geoblock service.
Handles loading, parsing, validating, and linting configuration from YAML files.

IP list entries support three forms (issue #7):
- literal IP:            "71.218.154.144"
- CIDR network:          "10.0.0.0/8"
- hostname (DDNS):       "home.example.com"  (resolved with TTL cache)
"""

import ipaddress
import logging
import os
import re
import fnmatch
import socket
import time

import yaml

from .blocklist_fetcher import fetch_asn_list
from .geo_providers import create_provider, IPINFO_LITE_DB_PATH

logger = logging.getLogger(__name__)

# Configuration paths
DEFAULT_CONFIG_PATH = '/app/config.yaml'
CONFIG_PATH = os.getenv('CONFIG_PATH', DEFAULT_CONFIG_PATH)
CONFIG_EXAMPLE_PATH = '/app/config.example.yaml'
BLOCK_PAGE_PATH = '/app/block_page.html'
COUNTRY_DB_PATH = os.getenv('COUNTRY_DB_PATH', '/data/GeoLite2-Country.mmdb')
ASN_DB_PATH = os.getenv('ASN_DB_PATH', '/data/GeoLite2-ASN.mmdb')

# Default TTL (seconds) for hostname (DDNS) resolution in IP lists
DNS_TTL = int(os.getenv('DNS_TTL', '60'))


class HostnameResolver:
    """Resolve hostnames to IPs with a TTL cache (for DDNS entries)."""

    def __init__(self, ttl=None):
        self.ttl = ttl if ttl is not None else DNS_TTL
        self._cache = {}  # hostname -> (resolved_set, timestamp)

    def resolve(self, hostname):
        now = time.monotonic()
        entry = self._cache.get(hostname)
        if entry and (now - entry[1]) < self.ttl:
            return entry[0]
        try:
            infos = socket.getaddrinfo(hostname, None)
            ips = {info[4][0] for info in infos}
        except (socket.gaierror, UnicodeError) as e:
            logger.warning(f"DNS lookup failed for '{hostname}': {e}")
            # Serve stale on failure (better than locking out on a transient DNS blip)
            return entry[0] if entry else set()
        self._cache[hostname] = (ips, now)
        return ips


class IPMatcher:
    """
    Match client IPs against a set of entries that may be literal IPs,
    CIDR networks, or hostnames (resolved with TTL cache).
    """

    def __init__(self, entries, resolver=None):
        self.entries = set(entries)
        self.exact = set()
        self.networks = []
        self.hostnames = set()
        self.resolver = resolver or HostnameResolver()
        for entry in self.entries:
            entry = str(entry).strip()
            if not entry:
                continue
            if '/' in entry:
                try:
                    self.networks.append(ipaddress.ip_network(entry, strict=False))
                    continue
                except ValueError:
                    logger.warning(f"Invalid CIDR entry: {entry}")
                    continue
            try:
                self.exact.add(str(ipaddress.ip_address(entry)))
            except ValueError:
                # Not an IP or CIDR — treat as hostname (DDNS)
                self.hostnames.add(entry.lower())

    def matches(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if str(ip) in self.exact:
            return True
        for net in self.networks:
            if ip in net:
                return True
        for hostname in self.hostnames:
            if str(ip) in self.resolver.resolve(hostname):
                return True
        return False


class Config:
    """Configuration container for geoblock service."""
    
    def __init__(self, config_path=None):
        """Initialize and load configuration.

        config_path: explicit YAML path (used by ConfigManager for hot-reload).
        Falls back to the CONFIG_PATH env / module default when omitted.
        """
        self._config_path = config_path
        # Load YAML config
        self.raw_config = self._load_yaml_config()
        
        # Parse settings FIRST (needed by other parsers for cache_hours)
        settings = self.raw_config.get('settings', {})
        self.allow_lan = os.getenv('ALLOW_LAN', str(settings.get('allow_lan', True))).lower() == 'true'
        self.allow_unknown = os.getenv('ALLOW_UNKNOWN', str(settings.get('allow_unknown', True))).lower() == 'true'
        self.use_html_response = os.getenv('USE_HTML_RESPONSE', str(settings.get('use_html_response', True))).lower() == 'true'
        self.block_status = self._parse_block_status(
            os.getenv('BLOCK_STATUS', settings.get('block_status', 403)))
        self.cache_hours = int(os.getenv('CACHE_HOURS', str(settings.get('cache_hours', 168))))
        dns_ttl = int(os.getenv('DNS_TTL', str(settings.get('dns_ttl', DNS_TTL))))
        self.resolver = HostnameResolver(ttl=dns_ttl)
        
        # Parse IP configuration
        ip_config = self.raw_config.get('ip', {})
        self.ip_mode = ip_config.get('mode', 'disabled')
        self.ip_whitelist = set(ip_config.get('whitelist', []))
        self.ip_blacklist = set(ip_config.get('blacklist', []))
        self.ip_whitelist_matcher = IPMatcher(self.ip_whitelist, self.resolver)
        self.ip_blacklist_matcher = IPMatcher(self.ip_blacklist, self.resolver)
        
        # Parse user-agent configuration (requires cache_hours)
        self._parse_user_agent_config(self.raw_config.get('user_agent', {}))
        
        # Parse country configuration
        country_config = self.raw_config.get('countries', {})
        self.country_mode = country_config.get('mode', 'disabled')
        self.country_whitelist = [c.upper() for c in country_config.get('whitelist', [])]
        self.country_blacklist = [c.upper() for c in country_config.get('blacklist', [])]
        
        # Parse ASN configuration
        asn_config = self.raw_config.get('asn', {})
        self.asn_mode = asn_config.get('mode', 'disabled')
        
        # Parse ASN whitelist (supports simple integers or objects with user-agent restrictions)
        self.asn_whitelist = {}  # dict: {asn_number: [user_agent_patterns] or None}
        for entry in asn_config.get('whitelist', []):
            if isinstance(entry, int):
                # Simple format: just the ASN number (no restrictions)
                self.asn_whitelist[entry] = None
            elif isinstance(entry, dict) and 'asn' in entry:
                # Complex format: ASN with user-agent restrictions
                asn = entry['asn']
                user_agents = entry.get('user_agents', [])
                self.asn_whitelist[asn] = user_agents if user_agents else None
            else:
                logger.warning(f"Invalid ASN whitelist entry: {entry}")
        
        self.asn_blacklist = set(asn_config.get('blacklist', []))
        
        # Fetch and merge remote ASN lists
        self._fetch_remote_asn_lists(asn_config)
        
        # Load HTML template
        self.block_page_template = self._load_html_template()
        
        # Validate configuration
        self._validate_config()
        
        # Lint configuration (non-fatal warnings, issue #6)
        self.lint_warnings = self._lint_config()
        
        # Parse domain-specific configurations
        self.domain_configs = {}
        domains = self.raw_config.get('domains', {})
        if domains:
            logger.info(f"Parsing {len(domains)} domain-specific configuration(s)")
            for domain, domain_config in domains.items():
                try:
                    self.domain_configs[domain.lower()] = self._parse_domain_config(domain, domain_config)
                    logger.info(f"Loaded configuration for domain: {domain}")
                except Exception as e:
                    logger.error(f"Failed to parse domain config for {domain}: {e}")
        
        # Load geo provider (MaxMind default, or IPinfo Lite combined DB)
        self.geo_provider = create_provider(
            self.raw_config.get('geoip', {}),
            COUNTRY_DB_PATH,
            ASN_DB_PATH,
            IPINFO_LITE_DB_PATH,
        )
        # Back-compat attributes (tests / health)
        self.country_reader = getattr(self.geo_provider, 'country_reader', None)
        self.asn_reader = getattr(self.geo_provider, 'asn_reader', None)

        # Precompute merged Config objects per domain pattern (per-request
        # rebuild recompiled regexes on every hit). Domain configs are static —
        # build once at load, dict-lookup per request. Must run AFTER the geo
        # provider loads: domain objects are shallow copies of this instance's
        # attributes at copy time. A failure here raises so the whole load
        # fails — silently dropping a domain's strict rules while reporting
        # healthy is worse than keeping the last-good config.
        self._domain_config_cache = {}
        for pattern, parsed in self.domain_configs.items():
            self._domain_config_cache[pattern] = self._create_domain_config(parsed)
        
        # Log configuration
        self._log_config()
    
    def close(self):
        """Release database handles (called on hot-reload swap)."""
        try:
            self.geo_provider.close()
        except Exception:
            pass
    
    def _parse_domain_config(self, domain, domain_config):
        """
        Parse domain-specific configuration.
        
        Returns a dict with overrides and whether to extend (merge) or replace.
        """
        parsed = {
            '_domain': domain,
            'extend_global': domain_config.get('extend_global', False),
            'overrides': {}
        }
        
        # Parse each section if present
        for section in ['ip', 'countries', 'asn', 'user_agent', 'settings']:
            if section in domain_config and section != 'extend_global':
                parsed['overrides'][section] = domain_config[section]
        
        return parsed
    
    def get_config_for_domain(self, host):
        """
        Get configuration for a specific domain with overrides applied.
        
        Args:
            host: The Host header value (e.g., "api.example.com" or "api.example.com:443")
        
        Returns:
            Config object (either a new merged config or self if no domain match)
        """
        if not host:
            return self
        
        # Strip port if present (bracketed IPv6 literal hosts keep their form)
        if host.startswith('['):
            host = host.split(']')[0] + ']' if ']' in host else host
        else:
            host = host.split(':')[0]
        host = host.lower()
        
        # Exact match first
        if host in self.domain_configs:
            cached = self._domain_config_cache.get(host)
            return cached if cached is not None else self
        
        # Check for wildcard matches (*.example.com)
        for domain_pattern, domain_config in self.domain_configs.items():
            if '*' in domain_pattern and fnmatch.fnmatch(host, domain_pattern):
                logger.debug(f"Domain '{host}' matched pattern '{domain_pattern}'")
                cached = self._domain_config_cache.get(domain_pattern)
                return cached if cached is not None else self
        
        # No match, return global config
        return self
    
    def _create_domain_config(self, domain_config):
        """
        Create a new Config object with domain-specific overrides applied.
        
        Args:
            domain_config: Parsed domain configuration dict
        
        Returns:
            New Config object with merged configuration
        """
        # Create a shallow copy of self
        domain_obj = object.__new__(Config)
        
        # Copy all attributes from global config (skip the parent's own
        # domain caches — a domain object must not alias the parent's cache)
        for attr, value in self.__dict__.items():
            if attr not in ('domain_configs', '_domain_config_cache'):
                setattr(domain_obj, attr, value)
        
        # Apply overrides based on extend strategy
        is_extend = domain_config.get('extend_global', False)
        overrides = domain_config.get('overrides', {})
        
        # Apply IP overrides
        if 'ip' in overrides:
            ip_config = overrides['ip']
            if not is_extend or 'mode' in ip_config:
                domain_obj.ip_mode = ip_config.get('mode', self.ip_mode)
            if is_extend:
                # Extend: merge lists
                domain_obj.ip_whitelist = self.ip_whitelist | set(ip_config.get('whitelist', []))
                domain_obj.ip_blacklist = self.ip_blacklist | set(ip_config.get('blacklist', []))
            else:
                # Replace: use only domain config
                domain_obj.ip_whitelist = set(ip_config.get('whitelist', []))
                domain_obj.ip_blacklist = set(ip_config.get('blacklist', []))
            # Rebuild matchers for the new entry sets
            domain_obj.ip_whitelist_matcher = IPMatcher(domain_obj.ip_whitelist, self.resolver)
            domain_obj.ip_blacklist_matcher = IPMatcher(domain_obj.ip_blacklist, self.resolver)
        
        # Apply country overrides
        if 'countries' in overrides:
            country_config = overrides['countries']
            if not is_extend or 'mode' in country_config:
                domain_obj.country_mode = country_config.get('mode', self.country_mode)
            if is_extend:
                # Extend: merge lists
                domain_obj.country_whitelist = list(set(self.country_whitelist) | 
                                                   set(c.upper() for c in country_config.get('whitelist', [])))
                domain_obj.country_blacklist = list(set(self.country_blacklist) | 
                                                   set(c.upper() for c in country_config.get('blacklist', [])))
            else:
                # Replace: use only domain config
                domain_obj.country_whitelist = [c.upper() for c in country_config.get('whitelist', [])]
                domain_obj.country_blacklist = [c.upper() for c in country_config.get('blacklist', [])]
        
        # Apply ASN overrides
        if 'asn' in overrides:
            asn_config = overrides['asn']
            if not is_extend or 'mode' in asn_config:
                domain_obj.asn_mode = asn_config.get('mode', self.asn_mode)
            
            if is_extend:
                # Extend: merge lists
                domain_obj.asn_whitelist = dict(self.asn_whitelist)
                for entry in asn_config.get('whitelist', []):
                    if isinstance(entry, int):
                        domain_obj.asn_whitelist[entry] = None
                    elif isinstance(entry, dict) and 'asn' in entry:
                        asn = entry['asn']
                        user_agents = entry.get('user_agents', [])
                        domain_obj.asn_whitelist[asn] = user_agents if user_agents else None
                
                domain_obj.asn_blacklist = self.asn_blacklist | set(asn_config.get('blacklist', []))
            else:
                # Replace: use only domain config
                domain_obj.asn_whitelist = {}
                for entry in asn_config.get('whitelist', []):
                    if isinstance(entry, int):
                        domain_obj.asn_whitelist[entry] = None
                    elif isinstance(entry, dict) and 'asn' in entry:
                        asn = entry['asn']
                        user_agents = entry.get('user_agents', [])
                        domain_obj.asn_whitelist[asn] = user_agents if user_agents else None
                
                domain_obj.asn_blacklist = set(asn_config.get('blacklist', []))
        
        # Apply user_agent overrides
        if 'user_agent' in overrides:
            ua_config = overrides['user_agent']
            if not is_extend or 'mode' in ua_config:
                domain_obj.user_agent_mode = ua_config.get('mode', self.user_agent_mode)
            
            # For user-agent, we don't re-compile regexes for domains (performance reasons)
            # Users should use extend mode sparingly or accept global patterns
            if not is_extend:
                # Replace mode: recompile with domain-specific patterns only
                whitelist_entries = set(ua_config.get('whitelist', []))
                blacklist_entries = set(ua_config.get('blacklist', []))
                
                domain_obj.user_agent_whitelist_regex = self._compile_user_agent_regex(whitelist_entries)
                domain_obj.user_agent_blacklist_regex = self._compile_user_agent_regex(blacklist_entries)
                domain_obj.user_agent_whitelist_count = len(whitelist_entries)
                domain_obj.user_agent_blacklist_count = len(blacklist_entries)
            # Note: extend mode keeps global regex patterns (no merge for performance)
        
        # Apply settings overrides
        if 'settings' in overrides:
            settings = overrides['settings']
            if 'allow_lan' in settings:
                domain_obj.allow_lan = settings['allow_lan']
            if 'allow_unknown' in settings:
                domain_obj.allow_unknown = settings['allow_unknown']
            if 'use_html_response' in settings:
                domain_obj.use_html_response = settings['use_html_response']
            if 'block_status' in settings:
                domain_obj.block_status = self._parse_block_status(settings['block_status'])
        
        logger.debug(f"Created domain config for '{domain_config.get('_domain', 'unknown')}'")
        return domain_obj
    
    def _load_yaml_config(self):
        """Load configuration from YAML file."""
        explicit = self._config_path
        # Explicit path (from ConfigManager) wins, then env default, then example.
        config_paths = [explicit or CONFIG_PATH, CONFIG_EXAMPLE_PATH]

        for path in config_paths:
            try:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        config = yaml.safe_load(f) or {}
                        logger.info(f"Loaded configuration from {path}")
                        return config
            except Exception as e:
                logger.error(f"Failed to load config from {path}: {e}")
                raise

        # A user-set CONFIG_PATH pointing at a missing file is a
        # misconfiguration (typo'd mount) — fail loudly rather than silently
        # serving example rules or an allow-all empty config. The built-in
        # default falling back to the bundled example is documented behavior.
        if explicit and explicit != DEFAULT_CONFIG_PATH:
            raise FileNotFoundError(f"Config file not found: {explicit}")

        logger.warning("No config file found, using empty defaults")
        return {}
    
    def _parse_user_agent_config(self, ua_config):
        """Parse user-agent filtering configuration with regex optimization."""
        self.user_agent_mode = ua_config.get('mode', 'disabled').lower()
        
        if self.user_agent_mode not in ['whitelist', 'blacklist', 'disabled']:
            logger.warning(f"Invalid user_agent mode '{self.user_agent_mode}', defaulting to 'disabled'")
            self.user_agent_mode = 'disabled'
        
        # Fetch remote user-agent lists
        remote_whitelist = self._fetch_remote_user_agent_lists(ua_config.get('whitelist_urls', []))
        remote_blacklist = self._fetch_remote_user_agent_lists(ua_config.get('blacklist_urls', []))
        
        # Combine manual and remote entries
        whitelist_entries = set(ua_config.get('whitelist', [])) | remote_whitelist
        blacklist_entries = set(ua_config.get('blacklist', [])) | remote_blacklist
        
        # Compile regex patterns for efficient substring matching
        self.user_agent_whitelist_regex = self._compile_user_agent_regex(whitelist_entries)
        self.user_agent_blacklist_regex = self._compile_user_agent_regex(blacklist_entries)
        
        # Store counts for logging/health endpoint
        self.user_agent_whitelist_count = len(whitelist_entries)
        self.user_agent_blacklist_count = len(blacklist_entries)
    
    def _compile_user_agent_regex(self, patterns):
        """Compile user-agent patterns into a single optimized regex for substring matching."""
        if not patterns:
            return None
        
        # Escape special regex characters and join with alternation
        escaped_patterns = [re.escape(pattern.strip()) for pattern in patterns if pattern.strip()]
        
        if not escaped_patterns:
            return None
        
        # Combine into single regex: (pattern1|pattern2|pattern3|...)
        combined_pattern = '|'.join(escaped_patterns)
        
        # Compile with case-insensitive flag for substring matching
        return re.compile(combined_pattern, re.IGNORECASE)
    
    def _fetch_remote_user_agent_lists(self, urls):
        """Fetch user-agent lists from remote URLs."""
        if not urls:
            return set()
        
        logger.info(f"Fetching user-agent lists from {len(urls)} source(s)")
        from .blocklist_fetcher import fetch_text_list
        all_entries = set()
        
        for url in urls:
            try:
                entries = fetch_text_list(
                    url,
                    cache_hours=self.cache_hours,
                    list_type='user-agent'
                )
                all_entries.update(entries)
                logger.info(f"Loaded {len(entries)} user-agents from {url}")
            except Exception as e:
                logger.error(f"Failed to fetch user-agent list from {url}: {e}")
        
        return all_entries
    
    def _fetch_remote_asn_lists(self, asn_config):
        """Fetch and merge remote ASN lists with local lists."""
        # Fetch blacklist URLs
        blacklist_urls = asn_config.get('blacklist_urls', [])
        if blacklist_urls:
            logger.info(f"Fetching ASN lists from {len(blacklist_urls)} source(s)")
            manual_count = len(asn_config.get('blacklist', []))
            for source in blacklist_urls:
                remote_asns = fetch_asn_list(source, cache_hours=self.cache_hours)
                self.asn_blacklist.update(remote_asns)
            logger.info(f"Total ASN blacklist size: {len(self.asn_blacklist)} "
                       f"(including {manual_count} manual entries)")
        
        # Fetch whitelist URLs
        whitelist_urls = asn_config.get('whitelist_urls', [])
        if whitelist_urls:
            logger.info(f"Fetching ASN whitelist from {len(whitelist_urls)} source(s)")
            for source in whitelist_urls:
                remote_asns = fetch_asn_list(source, cache_hours=self.cache_hours)
                # asn_whitelist is a dict {asn: user_agent_patterns|None} —
                # dict.update(list_of_ints) raises TypeError; insert per-entry.
                for asn_num in remote_asns:
                    self.asn_whitelist[int(asn_num)] = None
            logger.info(f"Total ASN whitelist size: {len(self.asn_whitelist)}")
    
    def _load_html_template(self):
        """Load HTML block page template.

        Path is BLOCK_PAGE_PATH env or settings.block_page (default
        /app/block_page.html). A missing/unreadable file falls back to JSON
        block responses with a loud warning (service keeps working, just
        without the HTML page).
        """
        settings = self.raw_config.get('settings', {})
        path = os.getenv('BLOCK_PAGE_PATH', settings.get('block_page', BLOCK_PAGE_PATH))
        try:
            with open(path, 'r') as f:
                template = f.read()
            logger.info(f"Loaded HTML block page template from {path}")
            return template
        except Exception as e:
            logger.warning(f"Could not load HTML template {path}: {e}, using JSON responses only")
            return None
    
    @staticmethod
    def _parse_block_status(value):
        """block_status: HTTP status returned on block. 403 (default) or 404.

        404 is a legit hardening choice — blocked clients can't confirm the
        route exists. Anything else is a config error, not a silent fallback.
        """
        try:
            status = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"block_status must be 403 or 404, got {value!r}")
        if status not in (403, 404):
            raise ValueError(f"block_status must be 403 or 404, got {status}")
        return status

    def _validate_config(self):
        """Validate configuration settings."""
        valid_modes = ('whitelist', 'blacklist', 'disabled')
        for name, mode in (('country', self.country_mode), ('asn', self.asn_mode),
                           ('ip', self.ip_mode), ('user_agent', self.user_agent_mode)):
            if mode not in valid_modes:
                raise ValueError(
                    f"Set {name} mode to one of {valid_modes}, got '{mode}'"
                )
    
    def _lint_config(self):
        """
        Non-fatal config hygiene checks (issue #6). Returns a list of warning
        strings. Also logged at startup. Contradictions and footguns are
        surfaced without breaking behavior.
        """
        warnings = []
        
        # ASN in both whitelist and blacklist
        asn_overlap = set(self.asn_whitelist.keys()) & set(self.asn_blacklist)
        if asn_overlap:
            warnings.append(
                f"ASN(s) in BOTH asn.whitelist and asn.blacklist: {sorted(asn_overlap)}. "
                "Whitelist wins (blacklist exception); if intentional, add a comment, "
                "otherwise remove one side."
            )
        
        # Country in both lists
        country_overlap = set(self.country_whitelist) & set(self.country_blacklist)
        if country_overlap:
            warnings.append(
                f"Country code(s) in BOTH countries.whitelist and countries.blacklist: "
                f"{sorted(country_overlap)}."
            )
        
        # IP in both lists
        ip_overlap = self.ip_whitelist & self.ip_blacklist
        if ip_overlap:
            warnings.append(
                f"IP entry(ies) in BOTH ip.whitelist and ip.blacklist: {sorted(ip_overlap)}."
            )
        
        # Overly broad user-agent substrings
        broad = {'bot', 'crawler', 'spider', 'crawl'}
        ua_blacklist = set()
        if self.user_agent_mode == 'blacklist' and self.user_agent_blacklist_regex:
            # Recover manual entries from raw config for linting (remote lists
            # are curated; manual broad entries are the footgun)
            ua_blacklist = {str(e).lower() for e in
                            self.raw_config.get('user_agent', {}).get('blacklist', [])}
        broad_hits = ua_blacklist & broad
        if broad_hits:
            warnings.append(
                f"User-agent blacklist contains broad substring(s) {sorted(broad_hits)} — "
                "substring match blocks any UA containing them (e.g. 'robot', 'Abbott'). "
                "Narrow the pattern (e.g. 'bot/' or a full UA) or rely on the curated "
                "remote bad-bot list instead."
            )
        
        # Whitelist mode with empty list = block everything
        if self.country_mode == 'whitelist' and not self.country_whitelist:
            warnings.append("countries.mode=whitelist but countries.whitelist is empty — all country lookups will block.")
        if self.asn_mode == 'whitelist' and not self.asn_whitelist:
            warnings.append("asn.mode=whitelist but asn.whitelist is empty — all ASN lookups will block.")
        if self.ip_mode == 'whitelist' and not self.ip_whitelist:
            warnings.append("ip.mode=whitelist but ip.whitelist is empty — all IPs will block.")
        
        for w in warnings:
            logger.warning(f"CONFIG LINT: {w}")
        return warnings
    
    def _load_country_db(self):
        """Deprecated: kept for back-compat; provider handles DB loading."""
        return getattr(self.geo_provider, 'country_reader', None)
    
    def _load_asn_db(self):
        """Deprecated: kept for back-compat; provider handles DB loading."""
        return getattr(self.geo_provider, 'asn_reader', None)
    
    def _log_config(self):
        """Log configuration details."""
        logger.info("Configuration:")
        logger.info(f"  Geo provider: {self.geo_provider.name}")
        logger.info(f"  Country mode: {self.country_mode}")
        logger.info(f"  Country whitelist: {self.country_whitelist}")
        logger.info(f"  Country blacklist: {self.country_blacklist}")
        logger.info(f"  ASN mode: {self.asn_mode}")
        logger.info(f"  User-Agent mode: {self.user_agent_mode}")
        if self.user_agent_mode != 'disabled':
            logger.info(f"  User-Agent whitelist: {self.user_agent_whitelist_count} patterns")
            logger.info(f"  User-Agent blacklist: {self.user_agent_blacklist_count} patterns")
        logger.info(f"  IP mode: {self.ip_mode}")
        logger.info(f"  IP whitelist: {self.ip_whitelist}")
        logger.info(f"  IP blacklist: {self.ip_blacklist}")
        logger.info(f"  ASN whitelist: {len(self.asn_whitelist)} total, "
                   f"{sum(1 for p in self.asn_whitelist.values() if p)} conditional")
        logger.info(f"  ASN blacklist: {len(self.asn_blacklist)} entries")
        logger.info(f"  ALLOW_LAN: {self.allow_lan}")
        logger.info(f"  ALLOW_UNKNOWN: {self.allow_unknown}")
        if self.lint_warnings:
            logger.warning(f"  Config lint: {len(self.lint_warnings)} warning(s) — see above")
        if self.domain_configs:
            logger.info(f"  Domain-specific configs: {len(self.domain_configs)} domain(s)")
            for domain in self.domain_configs.keys():
                logger.info(f"    - {domain}")


def lint_config_file(path):
    """
    Lint a config file without starting the service (issue #6).
    Returns (warnings, errors). Errors are fatal (invalid modes/YAML).
    """
    warnings, errors = [], []
    try:
        with open(path, 'r') as f:
            raw = yaml.safe_load(f)
    except Exception as e:
        return warnings, [f"YAML parse error: {e}"]
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        return warnings, ["Config root must be a mapping"]

    valid_modes = ('whitelist', 'blacklist', 'disabled')
    for section in ('ip', 'countries', 'asn', 'user_agent'):
        mode = (raw.get(section) or {}).get('mode', 'disabled')
        if mode not in valid_modes:
            errors.append(f"{section}.mode='{mode}' is not one of {valid_modes}")

    asn_cfg = raw.get('asn') or {}
    wl = set()
    for entry in asn_cfg.get('whitelist', []) or []:
        if isinstance(entry, int):
            wl.add(entry)
        elif isinstance(entry, dict) and 'asn' in entry:
            wl.add(entry['asn'])
    bl = set(asn_cfg.get('blacklist', []) or [])
    overlap = wl & bl
    if overlap:
        warnings.append(f"ASN(s) in both asn.whitelist and asn.blacklist: {sorted(overlap)}")

    c_cfg = raw.get('countries') or {}
    c_overlap = {c.upper() for c in c_cfg.get('whitelist', []) or []} & \
                {c.upper() for c in c_cfg.get('blacklist', []) or []}
    if c_overlap:
        warnings.append(f"Country code(s) in both lists: {sorted(c_overlap)}")

    i_cfg = raw.get('ip') or {}
    i_overlap = set(i_cfg.get('whitelist', []) or []) & set(i_cfg.get('blacklist', []) or [])
    if i_overlap:
        warnings.append(f"IP entry(ies) in both lists: {sorted(i_overlap)}")

    ua_cfg = raw.get('user_agent') or {}
    broad = {'bot', 'crawler', 'spider', 'crawl'}
    broad_hits = {str(e).lower() for e in ua_cfg.get('blacklist', []) or []} & broad
    if broad_hits:
        warnings.append(
            f"Broad user-agent substring(s) {sorted(broad_hits)} — substring match has "
            "false-positive risk; narrow or rely on the curated remote list."
        )

    return warnings, errors


if __name__ == '__main__':
    import sys
    target = sys.argv[2] if len(sys.argv) > 2 and sys.argv[1] == '--lint' else \
             sys.argv[1] if len(sys.argv) > 1 else CONFIG_PATH
    warns, errs = lint_config_file(target)
    for w in warns:
        print(f"WARN: {w}")
    for e in errs:
        print(f"ERROR: {e}")
    if errs:
        print(f"\n{len(errs)} error(s), {len(warns)} warning(s) in {target}")
        sys.exit(1)
    print(f"OK: {target} valid ({len(warns)} warning(s))")
