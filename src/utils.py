"""
Utility functions for IP handling and response rendering.
"""

import ipaddress
import uuid
import re
import logging
from datetime import datetime
from flask import request, jsonify, Response

logger = logging.getLogger(__name__)


def is_private_ip(ip_str):
    """
    Check if IP address is private/local.
    
    Args:
        ip_str: IP address as string
    
    Returns:
        True if IP is private, loopback, or link-local
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def get_client_ip():
    """
    Extract client IP from request headers.
    Checks X-Forwarded-For (set by reverse proxies like Traefik),
    then X-Real-IP, finally falls back to remote_addr.
    
    Returns:
        Client IP address as string
    """
    # Check X-Forwarded-For (Traefik sets this)
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        # Get the first IP in the chain (original client)
        ip = xff.split(',')[0].strip()
        if ip:
            return ip
    
    # Fallback to X-Real-IP
    xri = request.headers.get('X-Real-IP', '')
    if xri:
        return xri.strip()
    
    # Last resort: remote address
    return request.remote_addr


def render_block_page(reason, client_ip, country=None, asn=None, 
                     use_html_response=True, block_page_template=None,
                     status=403):
    """
    Render custom HTML block page or return JSON error response.
    
    Args:
        reason: Human-readable reason for blocking
        client_ip: Client's IP address
        country: Optional country information string
        asn: Optional ASN information string
        use_html_response: Whether to use HTML or JSON response
        block_page_template: HTML template string (optional)
        status: HTTP status to return on block (403 default, 404 supported)
    
    Returns:
        Flask Response object with the configured block status code
    """
    request_id = str(uuid.uuid4())[:8]
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # Return JSON if HTML is disabled or template not loaded
    if not use_html_response or not block_page_template:
        return jsonify({"error": reason, "ip": client_ip, "request_id": request_id}), status
    
    # Render HTML template
    html = block_page_template
    html = html.replace('{{reason}}', reason)
    html = html.replace('{{client_ip}}', client_ip)
    html = html.replace('{{timestamp}}', timestamp)
    html = html.replace('{{request_id}}', request_id)
    
    # Handle optional fields with simple template logic
    if country:
        html = html.replace('{{#country}}', '').replace('{{/country}}', '')
        html = html.replace('{{country}}', country)
    else:
        # Remove conditional section
        html = re.sub(r'{{#country}}.*?{{/country}}', '', html, flags=re.DOTALL)
    
    if asn:
        html = html.replace('{{#asn}}', '').replace('{{/asn}}', '')
        html = html.replace('{{asn}}', str(asn))
    else:
        # Remove conditional section
        html = re.sub(r'{{#asn}}.*?{{/asn}}', '', html, flags=re.DOTALL)
    
    return Response(html, status=status, mimetype='text/html')
