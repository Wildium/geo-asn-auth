"""
Geo lookup providers.

Normalizes lookups across database backends:
- MaxMind GeoLite2 (separate Country + ASN MMDB files) — the default.
- IPinfo Lite (single combined MMDB: country + ASN in one record).

Both providers return plain dicts so verification logic stays backend-agnostic:
  country_lookup(ip) -> {"iso_code": str|None, "name": str|None}
  asn_lookup(ip)     -> {"number": int, "org": str|None}

Raise geoip2.errors.AddressNotFoundError when the IP is not in the database,
so allow_unknown handling stays uniform.
"""

import logging
import os

import maxminddb
import geoip2.database
from geoip2.errors import AddressNotFoundError

logger = logging.getLogger(__name__)

IPINFO_LITE_DB_PATH = os.getenv('IPINFO_LITE_DB_PATH', '/data/ipinfo_lite.mmdb')


class MaxMindProvider:
    """MaxMind GeoLite2 Country + ASN databases (two MMDB files)."""

    name = 'maxmind'

    def __init__(self, country_reader, asn_reader):
        self.country_reader = country_reader
        self.asn_reader = asn_reader

    @property
    def country_available(self):
        return self.country_reader is not None

    @property
    def asn_available(self):
        return self.asn_reader is not None

    def country_lookup(self, ip):
        if not self.country_reader:
            raise AddressNotFoundError(f"No country database loaded (ip={ip})")
        resp = self.country_reader.country(ip)
        return {
            "iso_code": resp.country.iso_code,
            "name": resp.country.name,
        }

    def asn_lookup(self, ip):
        if not self.asn_reader:
            raise AddressNotFoundError(f"No ASN database loaded (ip={ip})")
        resp = self.asn_reader.asn(ip)
        return {
            "number": resp.autonomous_system_number,
            "org": resp.autonomous_system_organization,
        }

    def close(self):
        for reader in (self.country_reader, self.asn_reader):
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass


class IPinfoLiteProvider:
    """
    IPinfo Lite combined database (country + ASN in one MMDB).

    Opened with maxminddb directly (not geoip2): the IPinfo Lite DB has no
    MaxMind record classes, and geoip2's Reader exposes no public .get() —
    lookups must go through maxminddb.Reader.get(), which returns the raw dict.

    Schema per record: network, country, country_code, continent,
    continent_code, asn (int), as_name, as_domain.
    Download (free token):
        curl -L "https://ipinfo.io/data/ipinfo_lite.mmdb?token=$TOKEN" -o ipinfo_lite.mmdb
    Licensed CC-BY-SA 4.0.
    """

    name = 'ipinfo-lite'

    def __init__(self, reader):
        self.reader = reader

    @property
    def country_available(self):
        return self.reader is not None

    @property
    def asn_available(self):
        return self.reader is not None

    def _get(self, ip):
        if not self.reader:
            raise AddressNotFoundError(f"No IPinfo Lite database loaded (ip={ip})")
        record = self.reader.get(ip)
        if not record:
            raise AddressNotFoundError(f"IP not found in IPinfo Lite database (ip={ip})")
        return record

    def country_lookup(self, ip):
        record = self._get(ip)
        return {
            "iso_code": record.get('country_code'),
            "name": record.get('country'),
        }

    def asn_lookup(self, ip):
        record = self._get(ip)
        number = record.get('asn')
        if number is None:
            raise AddressNotFoundError(f"No ASN record in IPinfo Lite database (ip={ip})")
        return {
            "number": number,
            "org": record.get('as_name') or record.get('as_domain'),
        }

    def close(self):
        if self.reader is not None:
            try:
                self.reader.close()
            except Exception:
                pass


def create_provider(geoip_config, country_db_path, asn_db_path, ipinfo_db_path):
    """
    Build the configured geo provider.

    geoip_config: the optional `geoip:` section of config.yaml, e.g.
        geoip:
          provider: ipinfo-lite   # or: maxmind (default)
          ipinfo_lite_db: /data/ipinfo_lite.mmdb
    """
    geoip_config = geoip_config or {}
    provider = str(geoip_config.get('provider', 'maxmind')).lower()

    if provider == 'maxmind':
        country_reader = _open_mmdb(country_db_path, 'Country')
        asn_reader = _open_mmdb(asn_db_path, 'ASN')
        return MaxMindProvider(country_reader, asn_reader)

    if provider in ('ipinfo-lite', 'ipinfo_lite', 'ipinfo'):
        path = geoip_config.get('ipinfo_lite_db') or ipinfo_db_path
        reader = _open_maxminddb(path, 'IPinfo Lite')
        return IPinfoLiteProvider(reader)

    logger.error(f"Unknown geoip provider '{provider}', falling back to maxmind")
    country_reader = _open_mmdb(country_db_path, 'Country')
    asn_reader = _open_mmdb(asn_db_path, 'ASN')
    return MaxMindProvider(country_reader, asn_reader)


def _open_mmdb(path, label):
    try:
        if path and os.path.exists(path):
            reader = geoip2.database.Reader(path)
            logger.info(f"Loaded {label} database from {path}")
            return reader
        logger.warning(f"{label} database not found at {path}")
    except Exception as e:
        logger.error(f"Failed to load {label} database ({path}): {e}")
    return None


def _open_maxminddb(path, label):
    """Open an MMDB with the raw maxminddb client (dict records via .get())."""
    try:
        if path and os.path.exists(path):
            reader = maxminddb.open_database(path)
            logger.info(f"Loaded {label} database from {path}")
            return reader
        logger.warning(f"{label} database not found at {path}")
    except Exception as e:
        logger.error(f"Failed to load {label} database ({path}): {e}")
    return None
