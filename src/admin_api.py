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


def init_admin_api(manager, audit_path=None):
    """Wire the admin blueprint to the live ConfigManager."""
    global _manager, _audit_path
    _manager = manager
    _audit_path = audit_path or os.getenv('AUDIT_LOG_PATH', '/blocklists/audit.log')


def _admin_token():
    return os.getenv('ADMIN_TOKEN', '')


def require_admin(f):
    """Bearer-token gate. Fail closed: no ADMIN_TOKEN configured -> 404."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        token = _admin_token()
        if not token:
            # Admin API disabled entirely when no token is configured
            return jsonify({"error": "admin API disabled"}), 404
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({"error": "missing bearer token"}), 401
        supplied = auth[len('Bearer '):].strip()
        if not hmac.compare_digest(supplied, token):
            return jsonify({"error": "invalid token"}), 401
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
                with open(path, 'w') as f:
                    f.write(old_text)
                _manager.force_reload()
            return False, "reload failed — change rolled back"
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
