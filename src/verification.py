"""
Core verification logic for IP, country, and ASN-based blocking.
"""

import logging
import os
import fnmatch
from flask import jsonify, request
from geoip2.errors import AddressNotFoundError
from .utils import is_private_ip, get_client_ip, render_block_page

logger = logging.getLogger(__name__)


def verify_request(config):
    """
    Verify if the incoming request should be allowed or blocked.
    
    Args:
        config: Config object containing all configuration settings
    
    Returns:
        Flask Response tuple: (response_body, status_code)
        - ('', 200) for allowed requests
        - (error_response, 403) for blocked requests
    """
    try:
        # Get domain-specific configuration if available.
        # Host-first: the proxy pins Host per-vhost, so it can't be forged by
        # the client. X-Forwarded-Host is attacker-controlled unless the
        # fronting proxy is known to set it — opt in with TRUST_FORWARDED_HOST.
        host = request.headers.get('Host', '')
        if os.getenv('TRUST_FORWARDED_HOST', '').lower() == 'true':
            host = request.headers.get('X-Forwarded-Host') or host

        logger.debug(f"Request headers: Host={request.headers.get('Host')}, "
                     f"X-Forwarded-Host={request.headers.get('X-Forwarded-Host')}, "
                     f"X-Forwarded-For={request.headers.get('X-Forwarded-For')}, "
                     f"X-Real-IP={request.headers.get('X-Real-IP')}")

        domain_config = config.get_config_for_domain(host)

        if domain_config is not config:
            logger.debug(f"Using domain-specific config for: {host}")
        
        client_ip = get_client_ip()
        
        # Check IP whitelist/blacklist FIRST (before allow_lan bypass)
        # This ensures domain-specific IP whitelists work correctly
        ip_result = _check_ip(client_ip, domain_config)
        if ip_result is not None:
            return ip_result
        
        # Allow private IPs if configured (after IP whitelist/blacklist check)
        if domain_config.allow_lan and is_private_ip(client_ip):
            logger.debug(f"Allowing private IP: {client_ip}")
            return '', 200
        
        # Check user-agent whitelist/blacklist if configured
        ua_result = _check_user_agent(domain_config)
        if ua_result is not None:
            return ua_result
        
        # Check country if configured
        country_result = _check_country(client_ip, domain_config)
        if country_result is not None:
            return country_result
        
        # Check ASN if configured
        asn_result = _check_asn(client_ip, domain_config)
        if asn_result is not None:
            return asn_result
        
        # All checks passed
        return '', 200
        
    except Exception as e:
        logger.error(f"Error processing request: {e}", exc_info=True)
        # Fail open (allow) on errors to prevent service disruption
        return '', 200


def _check_user_agent(config):
    """Check user-agent whitelist/blacklist using compiled regex."""
    if config.user_agent_mode == 'disabled':
        return None
    
    user_agent = request.headers.get('User-Agent', '')
    
    if config.user_agent_mode == 'whitelist':
        if config.user_agent_whitelist_regex:
            if config.user_agent_whitelist_regex.search(user_agent):
                logger.debug(f"User-agent '{user_agent}' matched whitelist")
                return None  # Allowed
            else:
                logger.info(f"Blocked user-agent '{user_agent}' (not in whitelist)")
                return render_block_page(
                    "Your user-agent is not authorized.",
                    get_client_ip(),
                    use_html_response=config.use_html_response,
                    block_page_template=config.block_page_template
                )
        else:
            # No whitelist patterns = block all
            logger.info(f"Blocked user-agent '{user_agent}' (empty whitelist)")
            return render_block_page(
                "Your user-agent is not authorized.",
                get_client_ip(),
                use_html_response=config.use_html_response,
                block_page_template=config.block_page_template
            )
    
    elif config.user_agent_mode == 'blacklist':
        if config.user_agent_blacklist_regex and config.user_agent_blacklist_regex.search(user_agent):
            logger.info(f"Blocked user-agent '{user_agent}' (matched blacklist pattern)")
            return render_block_page(
                "Your user-agent has been blocked.",
                get_client_ip(),
                use_html_response=config.use_html_response,
                block_page_template=config.block_page_template
            )
    
    return None  # Allowed


def _check_ip(client_ip, config):
    """
    Check IP whitelist/blacklist.

    Entries may be literal IPs, CIDR networks, or hostnames (DDNS) —
    matching is delegated to the config's IPMatcher (issue #7).
    
    Returns:
        Response tuple if request should be blocked/allowed, None to continue checks
    """
    if config.ip_mode == 'disabled':
        logger.debug(f"IP check skipped (mode=disabled)")
        return None
    
    logger.debug(f"IP check: mode={config.ip_mode}, client_ip={client_ip}")
    
    # In blacklist mode: whitelist = bypass all checks, blacklist = immediate block
    if config.ip_mode == 'blacklist':
        if config.ip_whitelist and config.ip_whitelist_matcher.matches(client_ip):
            logger.info(f"Allowing IP {client_ip} (in IP whitelist, bypassing all checks)")
            return '', 200
        if config.ip_blacklist and config.ip_blacklist_matcher.matches(client_ip):
            logger.info(f"Blocked IP {client_ip} (in IP blacklist)")
            return render_block_page(
                "Your IP address has been blocked.",
                client_ip,
                use_html_response=config.use_html_response,
                block_page_template=config.block_page_template
            )
    
    # In whitelist mode: only whitelisted IPs allowed (others continue to country/ASN checks)
    elif config.ip_mode == 'whitelist':
        if config.ip_whitelist and config.ip_whitelist_matcher.matches(client_ip):
            logger.info(f"Allowing IP {client_ip} (in IP whitelist)")
            return '', 200
        else:
            # IP not in whitelist - BLOCK
            logger.info(f"Blocked IP {client_ip} (not in IP whitelist)")
            return render_block_page(
                "Your IP address is not authorized.",
                client_ip,
                use_html_response=config.use_html_response,
                block_page_template=config.block_page_template
            )
    
    return None


def _check_country(client_ip, config):
    """
    Check country whitelist/blacklist.
    
    Returns:
        Response tuple if request should be blocked, None to continue checks
    """
    provider = config.geo_provider
    if not provider.country_available or config.country_mode == 'disabled':
        return None
    
    try:
        info = provider.country_lookup(client_ip)
        country_code = info['iso_code']
        country_name = info['name']
        
        # Whitelist mode: only allow listed countries
        if config.country_mode == 'whitelist' and config.country_whitelist:
            if country_code not in config.country_whitelist:
                logger.info(f"Blocked IP {client_ip} from country {country_code} (not in whitelist)")
                return render_block_page(
                    f"Access from {country_name} ({country_code}) is not permitted.",
                    client_ip,
                    country=f"{country_name} ({country_code})",
                    use_html_response=config.use_html_response,
                    block_page_template=config.block_page_template
                )
        
        # Blacklist mode: block listed countries
        elif config.country_mode == 'blacklist' and config.country_blacklist:
            if country_code in config.country_blacklist:
                logger.info(f"Blocked IP {client_ip} from country {country_code} (in blacklist)")
                return render_block_page(
                    f"Access from {country_name} ({country_code}) is not permitted.",
                    client_ip,
                    country=f"{country_name} ({country_code})",
                    use_html_response=config.use_html_response,
                    block_page_template=config.block_page_template
                )
        
        logger.debug(f"Country check passed for {client_ip}: {country_code}")
        
    except AddressNotFoundError:
        logger.warning(f"Country not found for IP: {client_ip}")
        if not config.allow_unknown:
            logger.info(f"Blocked IP {client_ip} (country not found, ALLOW_UNKNOWN=false)")
            return jsonify({"error": "Geographic data unavailable"}), 403
    
    return None


def _check_asn(client_ip, config):
    """
    Check ASN whitelist/blacklist.
    
    Returns:
        Response tuple if request should be blocked, None to continue checks
    """
    provider = config.geo_provider
    if not provider.asn_available or config.asn_mode == 'disabled':
        return None
    
    try:
        info = provider.asn_lookup(client_ip)
        asn_number = info['number']
        asn_org = info['org']
        
        # Whitelist mode: only allow listed ASNs (strict mode)
        if config.asn_mode == 'whitelist':
            if not config.asn_whitelist or asn_number not in config.asn_whitelist:
                logger.info(f"Blocked IP {client_ip} from ASN {asn_number} (not in whitelist)")
                return render_block_page(
                    f"Access from your network (AS{asn_number}) is not permitted.",
                    client_ip,
                    asn=f"AS{asn_number} - {asn_org}",
                    use_html_response=config.use_html_response,
                    block_page_template=config.block_page_template
                )
        
        # Blacklist mode: block listed ASNs, but allow whitelisted exceptions
        elif config.asn_mode == 'blacklist':
            # Check whitelist first (exceptions to blacklist)
            if asn_number in config.asn_whitelist:
                user_agent_patterns = config.asn_whitelist[asn_number]
                
                # If no user-agent restrictions, allow immediately
                if user_agent_patterns is None:
                    logger.debug(f"Allowing IP {client_ip} from ASN {asn_number} (whitelisted exception)")
                else:
                    # Check if user-agent matches required patterns
                    user_agent = request.headers.get('User-Agent', '')
                    
                    matched = any(fnmatch.fnmatch(user_agent, pattern) for pattern in user_agent_patterns)
                    
                    if matched:
                        logger.info(f"Allowing IP {client_ip} from ASN {asn_number} (whitelisted with user-agent '{user_agent}')")
                    else:
                        logger.info(f"Blocked IP {client_ip} from ASN {asn_number} (whitelisted but user-agent '{user_agent}' doesn't match required patterns: {user_agent_patterns})")
                        return render_block_page(
                            f"Access from your network (AS{asn_number}) is not permitted.",
                            client_ip,
                            asn=f"AS{asn_number} - {asn_org}",
                            use_html_response=config.use_html_response,
                            block_page_template=config.block_page_template
                        )
            # Then check blacklist
            elif config.asn_blacklist and asn_number in config.asn_blacklist:
                logger.info(f"Blocked IP {client_ip} from ASN {asn_number} (in blacklist)")
                return render_block_page(
                    f"Access from your network (AS{asn_number}) is not permitted.",
                    client_ip,
                    asn=f"AS{asn_number} - {asn_org}",
                    use_html_response=config.use_html_response,
                    block_page_template=config.block_page_template
                )
        
        logger.debug(f"ASN check passed for {client_ip}: {asn_number}")
        
    except AddressNotFoundError:
        logger.warning(f"ASN not found for IP: {client_ip}")
        if not config.allow_unknown:
            logger.info(f"Blocked IP {client_ip} (ASN not found, ALLOW_UNKNOWN=false)")
            return render_block_page(
                "Network information unavailable. Access denied for security reasons.",
                client_ip,
                use_html_response=config.use_html_response,
                block_page_template=config.block_page_template
            )
    
    return None
