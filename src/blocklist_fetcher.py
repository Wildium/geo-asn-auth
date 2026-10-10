"""
Blocklist fetcher and caching functionality.
Handles downloading and caching ASN lists from remote URLs or local files.
"""

import os
import logging
import hashlib
import time
import requests

logger = logging.getLogger(__name__)

# Cache directory for downloaded ASN lists (configurable for tests/non-root runs).
# Created lazily on first fetch so importing the module never fails on a
# read-only or unwritable default path.
CACHE_DIR = os.getenv('BLOCKLIST_CACHE_DIR', '/blocklists')

# Remote list fetch timeout (s). Must stay well below the gunicorn worker
# timeout (30s) because config reloads — which re-fetch lists — run inline
# on the request path.
FETCH_TIMEOUT = float(os.getenv('BLOCKLIST_FETCH_TIMEOUT', '10'))

# Aggregate budget across ALL list fetches in one config load (s). Per-URL
# timeouts don't bound the total: N stale URLs = N x FETCH_TIMEOUT, which can
# exceed the worker timeout and SIGKILL the worker mid-reload. The check runs
# before each fetch, so worst case is budget + one in-flight FETCH_TIMEOUT.
FETCH_BUDGET_S = float(os.getenv('BLOCKLIST_FETCH_BUDGET_S', '15'))


class BlocklistLoadError(Exception):
    """A remote blocklist could not be loaded AND no stale cache exists to
    fall back to. Propagates out of the fetchers so the config load FAILS —
    a failed reload keeps the last-good config serving, which is safer than
    swapping in a config whose remote ASN/UA list was silently dropped
    (fail-open). Causes: fetch budget exhausted, HTTP error, DNS failure,
    connection refused, etc."""
    pass


def _read_cache_entries(cache_file, url, list_type):
    """Read+parse a cached list file. Any OSError (permissions, exists->open
    race, bad mount) becomes BlocklistLoadError so the load FAILS rather than
    the caller swallowing a raw error and silently dropping the blocklist."""
    try:
        with open(cache_file, 'r') as f:
            return {line.strip() for line in f if line.strip() and not line.strip().startswith('#')}
    except OSError as e:
        raise BlocklistLoadError(f"cannot read cached {list_type} list for {url}: {e}") from e


def fetch_text_list(url, cache_hours=168, list_type='text', deadline=None):
    """
    Fetch a text list from URL (one entry per line) with caching.
    Used for user-agent lists, generic text files, etc.
    
    Args:
        url: URL or local file path
        cache_hours: Cache duration in hours
        list_type: Type description for logging (e.g., 'user-agent', 'text')
        deadline: time.monotonic() value past which no fresh fetch is
            attempted (aggregate budget; falls back to stale cache)
    
    Returns:
        set: Set of non-empty, stripped lines from the file
    """
    cache_dir = CACHE_DIR
    try:
        os.makedirs(cache_dir, exist_ok=True)
    except OSError:
        pass
    
    # Generate cache filename based on URL
    url_hash = hashlib.md5(url.encode()).hexdigest()
    cache_file = os.path.join(cache_dir, f"{list_type}_{url_hash}.txt")
    
    # Check if cached file exists and is fresh
    if os.path.exists(cache_file):
        file_age_seconds = time.time() - os.path.getmtime(cache_file)
        file_age_hours = file_age_seconds / 3600
        
        if file_age_hours < cache_hours:
            logger.info(f"Using cached {list_type} list from {url} (age: {file_age_hours:.1f}h)")
            return _read_cache_entries(cache_file, url, list_type)
        else:
            logger.info(f"Cached {list_type} list from {url} expired (age: {file_age_hours:.1f}h), fetching fresh")
    
    # Fetch fresh list
    try:
        if url.startswith('file://') or url.startswith('/'):
            # Local file path
            local_path = url.replace('file://', '')
            with open(local_path, 'r') as f:
                content = f.read()
        else:
            # Aggregate budget: past the deadline, skip the network and fall
            # back to stale cache below — N slow URLs must not stack up past
            # the gunicorn worker timeout on the request path.
            if deadline is not None and time.monotonic() > deadline:
                raise BlocklistLoadError(f"fetch budget ({FETCH_BUDGET_S}s) exhausted")
            # Remote URL — keep the timeout well under the gunicorn worker
            # timeout (30s): a config reload runs inline on the request path,
            # and a slow blocklist URL must not stall the worker to SIGKILL.
            response = requests.get(url, timeout=FETCH_TIMEOUT)
            response.raise_for_status()
            content = response.text
        
        # Parse entries (one per line, skip empty lines and comments)
        entries = {line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith('#')}
        
        # Cache the content
        with open(cache_file, 'w') as f:
            f.write(content)
        
        logger.info(f"Fetched and cached {len(entries)} {list_type} entries from {url}")
        return entries
    
    except Exception as e:
        logger.error(f"Failed to fetch {list_type} list from {url}: {e}")
        
        # Try to use stale cache if available
        if os.path.exists(cache_file):
            logger.warning(f"Using stale cached {list_type} list from {url}")
            return _read_cache_entries(cache_file, url, list_type)
        
        # No cache to fall back to: an empty list here would swap in a config
        # with this blocklist silently dropped (fail-open). Fail the load so
        # the last-good config keeps serving.
        raise BlocklistLoadError(f"cannot load {list_type} list from {url}: {e}") from e


def fetch_asn_list(source, timeout=10, cache_hours=168, deadline=None):
    """
    Fetch ASN list from remote URL or local file path.
    
    Args:
        source: URL or file path to fetch ASN list from
        timeout: Request timeout in seconds (default: 10)
        cache_hours: Cache validity period in hours (default: 168 = 7 days)
        deadline: time.monotonic() value past which no fresh fetch is
            attempted (aggregate budget; falls back to stale cache)
    
    Returns:
        List of ASN numbers (integers)
    """
    try:
        # Handle local file paths
        if source.startswith('file://') or source.startswith('/'):
            file_path = source.replace('file://', '')
            logger.info(f"Reading ASN list from local file: {file_path}")
            with open(file_path, 'r') as f:
                content = f.read()
        else:
            # Handle remote URLs with caching
            content = _fetch_remote_asn_list(source, timeout, cache_hours, deadline=deadline)
        
        # Parse ASNs from content
        asns = _parse_asn_content(content, source)
        logger.info(f"Loaded {len(asns)} ASNs from {source}")
        return asns
        
    except BlocklistLoadError:
        # Must NOT be swallowed: an empty return here would swap in a config
        # with the remote ASN list silently dropped (fail-open for blacklist).
        # Propagate so the whole config load fails and last-good keeps serving.
        raise
    except FileNotFoundError as e:
        # A config-referenced local list that doesn't exist is a
        # misconfiguration (bad mount) — same fail-open if dropped silently.
        # Fail the load loudly; hot-reload recovers when the file appears.
        logger.error(f"Local file not found: {source}: {e}")
        raise BlocklistLoadError(f"local ASN list not found: {source}") from e
    except Exception as e:
        logger.error(f"Error loading ASN list from {source}: {e}")
        raise BlocklistLoadError(f"error loading ASN list from {source}: {e}") from e


def _fetch_remote_asn_list(source, timeout, cache_hours, deadline=None):
    """
    Fetch ASN list from remote URL with caching support.
    
    Args:
        source: URL to fetch from
        timeout: Request timeout in seconds
        cache_hours: Cache validity period in hours
        deadline: time.monotonic() past which no fresh fetch is attempted
    
    Returns:
        Content of the ASN list as string
    """
    # Generate cache filename from URL hash
    url_hash = hashlib.md5(source.encode()).hexdigest()
    cache_file = os.path.join(CACHE_DIR, f"asn_list_{url_hash}.txt")
    cache_time_file = os.path.join(CACHE_DIR, f"asn_list_{url_hash}.time")
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
    except OSError:
        pass
    
    # Check if cached file exists and is recent
    content = _read_cache_if_valid(cache_file, cache_time_file, cache_hours, source)
    
    # Fetch from URL if no valid cache
    if content is None:
        # Aggregate budget: past the deadline, skip the network. Serve stale
        # cache if we have it. If we don't, raise rather than return empty —
        # the config load must FAIL so the last-good config keeps serving.
        # Swallowing this would swap in a config with the remote ASN list
        # silently dropped, which is fail-open for asn.mode=blacklist.
        if deadline is not None and time.monotonic() > deadline:
            logger.warning(f"Fetch budget ({FETCH_BUDGET_S}s) exhausted for {source}")
            if os.path.exists(cache_file):
                logger.warning(f"Using STALE cached ASN list from {source}")
                with open(cache_file, 'r') as f:
                    return f.read()
            raise BlocklistLoadError(f"fetch budget exhausted, no stale cache for {source}")
        logger.info(f"Fetching ASN list from {source}")
        try:
            response = requests.get(source, timeout=timeout)
            response.raise_for_status()
            content = response.text
        except requests.exceptions.RequestException as e:
            # Ordinary fetch failure (404, DNS, refused, timeout): same policy
            # as budget exhaustion — stale cache or fail the load. Returning
            # empty here would silently drop the remote list (fail-open).
            if os.path.exists(cache_file):
                logger.warning(f"Using STALE cached ASN list from {source} after fetch error: {e}")
                with open(cache_file, 'r') as f:
                    return f.read()
            raise BlocklistLoadError(f"cannot fetch ASN list from {source}: {e}") from e
        
        # Save to cache
        _save_to_cache(cache_file, cache_time_file, content, source)
    
    return content


def _read_cache_if_valid(cache_file, cache_time_file, cache_hours, source):
    """
    Read cached ASN list if it exists and is still valid.
    
    Returns:
        Cached content as string, or None if cache is invalid/missing
    """
    if os.path.exists(cache_file) and os.path.exists(cache_time_file):
        try:
            with open(cache_time_file, 'r') as f:
                cache_timestamp = float(f.read().strip())
            
            # Check if cache is still valid
            age_hours = (time.time() - cache_timestamp) / 3600
            if age_hours < cache_hours:
                logger.info(f"Using cached ASN list from {source} (age: {age_hours:.1f}h)")
                with open(cache_file, 'r') as f:
                    return f.read()
            else:
                logger.info(f"Cache expired for {source} (age: {age_hours:.1f}h), fetching fresh data")
                return None
        except Exception as e:
            logger.warning(f"Error reading cache: {e}, fetching fresh data")
            return None
    
    return None


def _save_to_cache(cache_file, cache_time_file, content, source):
    """Save fetched content to cache files."""
    try:
        with open(cache_file, 'w') as f:
            f.write(content)
        with open(cache_time_file, 'w') as f:
            f.write(str(time.time()))
        logger.info(f"Cached ASN list from {source}")
    except Exception as e:
        logger.warning(f"Failed to cache ASN list: {e}")


def _parse_asn_content(content, source):
    """
    Parse ASN numbers from content.
    
    Args:
        content: Text content containing ASN numbers (one per line)
        source: Source identifier for logging
    
    Returns:
        List of ASN numbers (integers)
    """
    asns = []
    for line in content.splitlines():
        line = line.strip()
        # Skip comments and empty lines
        if not line or line.startswith('#'):
            continue
        # Try to parse as integer
        try:
            asn = int(line)
            asns.append(asn)
        except ValueError:
            continue
    
    return asns
