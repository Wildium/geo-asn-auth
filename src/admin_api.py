"""
Token-authed admin API for runtime config edits (issue #4).

Makes the blocker agent-operable: an AI assistant (or human) can add the next
VPN ASN over HTTPS without shell access. Write path:
    validate -> auto-backup (config.yaml.bak-<ts>) -> atomic write ->
    hot-reload -> audit log entry.

Auth: Bearer token from ADMIN_TOKEN env. If ADMIN_TOKEN is unset, the admin
API is disabled entirely (404) — fail closed.
"""

import functools
import hmac
import logging
import os
import re
import tempfile
import threading
import time

import yaml
from flask import Blueprint, jsonify, request

from .config import lint_config_file

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger('geoblock.audit')

admin_bp = Blueprint('admin', __name__)

# Injected by app.py at registration time
_manager = None
_audit_path = None

# ---------------------------------------------------------------------- #
# Per-IP throttle on failed admin auth (brute-force backstop).
# Counts only 401 auth failures (wrong/missing bearer token), not successful
# calls and not the 404 "admin disabled" path, so a legitimate admin is never
# rate-limited. In-memory and per-worker: a strong token makes this a
# belt-and-braces control, not the primary one.
# ---------------------------------------------------------------------- #
_FAIL_WINDOW_S = int(os.getenv('ADMIN_FAIL_WINDOW_S', '60'))
_FAIL_MAX = int(os.getenv('ADMIN_FAIL_MAX', '10'))
_FAIL_MAX_IPS = int(os.getenv('ADMIN_FAIL_MAX_IPS', '1000'))
_fail_counts = {}          # ip -> [timestamps of failures within window]
_fail_lock = threading.Lock()


def _client_ip():
    """Best-effort client IP for throttling. XFF is spoofable, but poisoning
    a throttle bucket only harms the attacker's own access — this is not an
    auth decision, so best-effort is acceptable."""
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or 'unknown'


def _throttled(ip):
    """True if this IP has exceeded the failure budget in the window.
    Returns (throttled, retry_after_s)."""
    now = time.monotonic()
    cutoff = now - _FAIL_WINDOW_S
    with _fail_lock:
        stamps = [t for t in _fail_counts.get(ip, ()) if t >= cutoff]
        if len(stamps) >= _FAIL_MAX:
            _fail_counts[ip] = stamps
            retry = int(_FAIL_WINDOW_S - (now - stamps[0])) + 1
            return True, max(retry, 1)
        return False, 0


def _record_failure(ip):
    now = time.monotonic()
    cutoff = now - _FAIL_WINDOW_S
    with _fail_lock:
        # Bound the dict: XFF is spoofable, so an attacker can spray unique
        # "IPs" and grow this without limit. Prune expired entries; if still
        # full, drop the oldest-seen bucket so memory stays bounded.
        expired = [k for k, v in _fail_counts.items()
                   if not v or v[-1] < cutoff]
        for k in expired:
            del _fail_counts[k]
        # <=0 disables the cap only if the operator explicitly opts out;
        # treat it as "don't track" rather than silently unbounded growth.
        if _FAIL_MAX_IPS <= 0:
            return
        expired = [k for k, v in _fail_counts.items()
                   if not v or v[-1] < cutoff]
        for k in expired:
            del _fail_counts[k]
        if len(_fail_counts) >= _FAIL_MAX_IPS:
            oldest = min(_fail_counts, key=lambda k: _fail_counts[k][0])
            del _fail_counts[oldest]
        stamps = [t for t in _fail_counts.get(ip, ()) if t >= cutoff]
        stamps.append(now)
        _fail_counts[ip] = stamps


def _reset_failures(ip):
    with _fail_lock:
        _fail_counts.pop(ip, None)


def init_admin_api(manager, audit_path=None):
    """Wire the admin blueprint to the live ConfigManager."""
    global _manager, _audit_path
    _manager = manager
    _audit_path = audit_path or os.getenv('AUDIT_LOG_PATH', '/blocklists/audit.log')


def _admin_token():
    return os.getenv('ADMIN_TOKEN', '')


def require_admin(f):
    """Bearer-token gate. Fail closed: no ADMIN_TOKEN configured -> 404.
    Failed attempts are throttled per-IP to blunt brute-force."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ip = _client_ip()
        throttled, retry = _throttled(ip)
        if throttled:
            resp = jsonify({"error": "too many failed attempts"})
            resp.status_code = 429
            resp.headers['Retry-After'] = str(retry)
            return resp
        token = _admin_token()
        if not token:
            # Admin API disabled entirely when no token is configured
            return jsonify({"error": "admin API disabled"}), 404
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            _record_failure(ip)
            return jsonify({"error": "missing bearer token"}), 401
        supplied = auth[len('Bearer '):].strip()
        if not hmac.compare_digest(supplied, token):
            _record_failure(ip)
            return jsonify({"error": "invalid token"}), 401
        _reset_failures(ip)
        return f(*args, **kwargs)
    return wrapper


def _config_path():
    return _manager.config_path()


def _audit(action, detail, actor='admin-api'):
    ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    line = f"{ts} actor={actor} action={action} {detail}"
    audit_logger.info(line)
    try:
        with open(_audit_path, 'a') as f:
            f.write(line + "\n")
    except Exception as e:
        logger.warning(f"Failed to write audit log: {e}")


def _read_raw_config():
    path = _config_path()
    if not os.path.exists(path):
        return {}
    with open(path, 'r') as f:
        return yaml.safe_load(f) or {}


def _write_config(raw):
    """
    Validate -> backup -> atomic write -> hot-reload.
    Returns (ok, error_message). On reload failure the file is rolled back.
    """
    path = _config_path()
    # Serialize to a temp file first, then lint the candidate before touching
    # the live file.
    fd, tmp_path = tempfile.mkstemp(suffix='.yaml', dir=os.path.dirname(path) or '.')
    try:
        with os.fdopen(fd, 'w') as f:
            yaml.safe_dump(raw, f, default_flow_style=False, sort_keys=False)
        warns, errs = lint_config_file(tmp_path)
        if errs:
            return False, f"validation failed: {'; '.join(errs)}"

        # Backup the current live config
        if os.path.exists(path):
            bak = f"{path}.bak-{int(time.time())}"
            try:
                with open(path, 'rb') as src, open(bak, 'wb') as dst:
                    dst.write(src.read())
            except Exception as e:
                logger.warning(f"Backup failed: {e}")

        # Atomic replace
        old_text = open(path).read() if os.path.exists(path) else None
        os.replace(tmp_path, path)

        # Hot-reload; roll back on failure
        if not _manager.force_reload():
            if old_text is not None:
                # Atomic restore — a concurrent poll-reload must never read a
                # half-written config off the rollback path.
                rb_path = path + '.rollback'
                rolled_back = False
                try:
                    with open(rb_path, 'w') as f:
                        f.write(old_text)
                    os.replace(rb_path, path)
                    rolled_back = True
                except Exception as e:
                    logger.critical(f"Config rollback FAILED ({e}) — fix {path} manually")
                    if os.path.exists(rb_path):
                        try:
                            os.unlink(rb_path)
                        except OSError:
                            pass
                if rolled_back:
                    _manager.force_reload()
                    return False, "reload failed — change rolled back"
                # Rollback failed: the rejected change is what's on disk. Do
                # NOT force_reload() — that could succeed with a fresh fetch
                # budget and silently apply the rejected change while we
                # report failure. Last-good keeps serving; tell the truth.
                return False, (f"reload failed AND rollback failed — {path} still "
                               f"contains the rejected change; fix it manually")
            return False, "reload failed — no previous config to roll back to"
        return True, None
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ---------------------------------------------------------------------- #
# Routes
# ---------------------------------------------------------------------- #
@admin_bp.route('/config', methods=['GET'])
@require_admin
def get_config():
    """Current effective config (secrets never stored in config.yaml)."""
    try:
        raw = _read_raw_config()
    except Exception as e:
        return jsonify({"error": f"could not read config: {e}"}), 500
    cfg = _manager.current()
    return jsonify({
        "config": raw,
        "lint_warnings": cfg.lint_warnings,
        "reload": _manager.status(),
    })


def _section_get(section):
    cfg = _manager.current()
    if section == 'ip-whitelist':
        return {"entries": sorted(cfg.ip_whitelist, key=str)}
    if section == 'ip-blacklist':
        return {"entries": sorted(cfg.ip_blacklist, key=str)}
    if section == 'asn-whitelist':
        return {"entries": [{"asn": a, "user_agents": ua} for a, ua in cfg.asn_whitelist.items()]}
    if section == 'asn-blacklist':
        return {"entries": sorted(cfg.asn_blacklist)}
    if section == 'country-whitelist':
        return {"entries": cfg.country_whitelist}
    if section == 'country-blacklist':
        return {"entries": cfg.country_blacklist}
    if section == 'user-agent-blacklist':
        raw = _read_raw_config().get('user_agent', {})
        return {"entries": raw.get('blacklist', [])}
    if section == 'user-agent-whitelist':
        raw = _read_raw_config().get('user_agent', {})
        return {"entries": raw.get('whitelist', [])}
    return None


def _section_mutate(section, body):
    """
    Apply a surgical edit to raw config for a section.
    body: {"add": [...], "remove": [...]} — either or both.
    Returns (raw, changed_desc) or raises ValueError.
    """
    raw = _read_raw_config()
    adds = body.get('add', []) or []
    removes = {str(x) for x in (body.get('remove', []) or [])}

    def key(v):
        return str(v)

    if section in ('ip-whitelist', 'ip-blacklist'):
        sec = raw.setdefault('ip', {})
        field = 'whitelist' if 'white' in section else 'blacklist'
        entries = [str(e) for e in sec.get(field, []) or []]
        entries = [e for e in entries if e not in removes]
        for a in adds:
            e = str(a)
            if e not in entries:
                entries.append(e)
        sec[field] = entries
    elif section in ('country-whitelist', 'country-blacklist'):
        sec = raw.setdefault('countries', {})
        field = 'whitelist' if 'white' in section else 'blacklist'
        entries = [str(e).upper() for e in sec.get(field, []) or []]
        entries = [e for e in entries if e not in {r.upper() for r in removes}]
        for a in adds:
            e = str(a).upper()
            if e not in entries:
                entries.append(e)
        sec[field] = entries
    elif section == 'asn-blacklist':
        sec = raw.setdefault('asn', {})
        entries = [int(e) for e in sec.get('blacklist', []) or []]
        rem = {int(r) for r in removes}
        entries = [e for e in entries if e not in rem]
        for a in adds:
            e = int(a)
            if e not in entries:
                entries.append(e)
        sec['blacklist'] = entries
    elif section == 'asn-whitelist':
        sec = raw.setdefault('asn', {})
        entries = sec.get('whitelist', []) or []
        rem = {int(r) for r in removes}
        kept = []
        for e in entries:
            asn = e['asn'] if isinstance(e, dict) else e
            if int(asn) not in rem:
                kept.append(e)
        for a in adds:
            if isinstance(a, dict) and 'asn' in a:
                kept.append(a)
            else:
                kept.append(int(a))
        sec['whitelist'] = kept
    elif section in ('user-agent-whitelist', 'user-agent-blacklist'):
        sec = raw.setdefault('user_agent', {})
        field = 'whitelist' if 'white' in section else 'blacklist'
        entries = [str(e) for e in sec.get(field, []) or []]
        entries = [e for e in entries if e not in removes]
        for a in adds:
            e = str(a)
            if e not in entries:
                entries.append(e)
        sec[field] = entries
    else:
        raise ValueError(f"unknown section: {section}")

    return raw, f"section={section} add={adds} remove={sorted(removes)}"


_SECTIONS = ('ip-whitelist', 'ip-blacklist', 'asn-whitelist', 'asn-blacklist',
             'country-whitelist', 'country-blacklist',
             'user-agent-whitelist', 'user-agent-blacklist')


def _register_section_routes():
    for section in _SECTIONS:
        def make_get(s=section):
            @require_admin
            def view():
                data = _section_get(s)
                if data is None:
                    return jsonify({"error": "unknown section"}), 404
                return jsonify(data)
            return view

        def make_put(s=section):
            @require_admin
            def view():
                body = request.get_json(silent=True) or {}
                try:
                    raw, desc = _section_mutate(s, body)
                except (ValueError, TypeError) as e:
                    return jsonify({"error": f"invalid request: {e}"}), 400
                ok, err = _write_config(raw)
                if not ok:
                    _audit('edit_failed', f"{s} error={err}")
                    return jsonify({"error": err}), 422
                _audit('edit', desc)
                return jsonify({"ok": True, "reload": _manager.status()})
            return view

        admin_bp.add_url_rule(f'/{section}', f'get_{section}', make_get(), methods=['GET'])
        admin_bp.add_url_rule(f'/{section}', f'put_{section}', make_put(), methods=['PUT'])


_register_section_routes()


@admin_bp.route('/reload', methods=['POST'])
@require_admin
def reload_now():
    ok = _manager.force_reload()
    status = 200 if ok else 500
    return jsonify({"ok": ok, "reload": _manager.status()}), status
