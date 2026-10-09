"""
Geoblock Service - Flask application for IP/country/ASN-based access control.
Provides ForwardAuth endpoint for Traefik reverse proxy.
"""

import logging
import os
import signal

from flask import Flask, jsonify, request

from .admin_api import admin_bp, init_admin_api
from .manager import ConfigManager
from .verification import verify_request

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Filter to suppress health check logs
class HealthCheckFilter(logging.Filter):
    def filter(self, record):
        # Suppress logs for /health endpoint
        return '/health' not in record.getMessage()

# Apply filter to werkzeug logger (Flask's HTTP request logger)
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.addFilter(HealthCheckFilter())

# Initialize Flask app
app = Flask(__name__)

# Live config with hot-reload support (issue #3)
manager = ConfigManager()


def _sighup_handler(signum, frame):
    logger.info("SIGHUP received — reloading config")
    manager.force_reload()


try:
    signal.signal(signal.SIGHUP, _sighup_handler)
except (ValueError, AttributeError, OSError):
    # Not on the main thread, or platform without SIGHUP (Windows) — mtime
    # polling still covers hot-reload.
    logger.debug("SIGHUP handler not installed (polling still active)")

# Admin API (issue #4) — gated by ADMIN_TOKEN; disabled when unset
init_admin_api(manager)
app.register_blueprint(admin_bp, url_prefix='/admin')


@app.route('/verify', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
def verify():
    """ForwardAuth verification endpoint."""
    return verify_request(manager.current())


@app.route('/health')
def health():
    """
    Minimal health check (issue #8): reveals no rule contents or counts.
    Full config summary lives behind ADMIN_TOKEN at /health/detail.
    """
    status = manager.status()
    cfg = manager.current()
    return jsonify({
        "status": "healthy" if status["config_loaded"] else "degraded",
        "dbs_loaded": bool(cfg.geo_provider.country_available or cfg.geo_provider.asn_available),
        "config_loaded": status["config_loaded"],
        "last_reload": status["last_reload"],
        "last_reload_error": status["last_reload_error"],
    }), 200


@app.route('/health/detail')
def health_detail():
    """Full config summary — requires ADMIN_TOKEN (issue #8)."""
    token = os.getenv('ADMIN_TOKEN', '')
    if not token:
        return jsonify({"error": "detail endpoint disabled (no ADMIN_TOKEN)"}), 404
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer ') or auth[len('Bearer '):].strip() != token:
        return jsonify({"error": "unauthorized"}), 401

    config = manager.current()
    status = {
        "status": "healthy" if manager.status()["config_loaded"] else "degraded",
        "geo_provider": config.geo_provider.name,
        "country_db": config.geo_provider.country_available,
        "asn_db": config.geo_provider.asn_available,
        "reload": manager.status(),
        "lint_warnings": config.lint_warnings,
        "config": {
            "ip_mode": config.ip_mode,
            "ip_whitelist_count": len(config.ip_whitelist),
            "ip_blacklist_count": len(config.ip_blacklist),
            "user_agent_mode": config.user_agent_mode,
            "user_agent_whitelist_count": config.user_agent_whitelist_count,
            "user_agent_blacklist_count": config.user_agent_blacklist_count,
            "country_mode": config.country_mode,
            "country_whitelist": config.country_whitelist,
            "country_blacklist": config.country_blacklist,
            "asn_mode": config.asn_mode,
            "asn_whitelist_count": len(config.asn_whitelist),
            "asn_whitelist_conditional_count": sum(1 for patterns in config.asn_whitelist.values() if patterns is not None),
            "asn_blacklist_count": len(config.asn_blacklist),
            "allow_lan": config.allow_lan,
            "allow_unknown": config.allow_unknown
        }
    }
    return jsonify(status), 200


# Web admin UI (issue #5) — thin frontend over the admin API
from .web_ui import register_ui_routes
register_ui_routes(app)


if __name__ == '__main__':
    port = int(os.getenv('PORT', 9876))
    app.run(host='0.0.0.0', port=port, debug=False)
