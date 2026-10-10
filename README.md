# geo-asn-auth

A Flask ForwardAuth service for your reverse proxy that blocks traffic based on country, ASN, and user-agent using MaxMind databases.

[![Docker Image](https://img.shields.io/badge/docker-ghcr.io-blue)](https://ghcr.io)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Quick Start

There are 4 main requirements to run this application.

* The `docker-compose.yml` file
* The `GeoLite2-city.mmdb` and `GeoLite2-ASN.mmdb` maxmind databases
* A `config.yaml` file
* Configure your reverse proxy (see [Traefik](#traefik), [Nginx](#nginx), or [Caddy](#caddy) instructions)

### Using Docker Compose

```yml "docker-compose.yml"
services:
  geo-asn-auth:
    image: ghcr.io/wildium/geo-asn-auth:latest
    # user: "1001:1001"
    container_name: geo-asn-auth
    restart: unless-stopped
    volumes:
      # Mount MaxMind databases (required) This can be a shared location for other Pangolin services
      - ./config/maxmind:/data:ro
      - ./geoblock/config.yaml:/app/config.yaml:ro
    # environment:
      # - PORT=9876 # Service port (default: 9876)

    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:9876/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
```

See [docker-compose.example.yml](docker-compose.example.yml) for a complete example.

### Maxmind Database

If you do not already have the maxmind databases being pulled, then you can add this to your compose stack

```yml
  maxmind-updater:
    image: maxmindinc/geoipupdate:latest
    container_name: maxmind-updater
    restart: unless-stopped
    volumes:
      - ./config/maxmind:/usr/share/GeoIP
    environment:
      - GEOIPUPDATE_ACCOUNT_ID=${MAXMIND_ACCOUNT_ID}
      - GEOIPUPDATE_LICENSE_KEY=${MAXMIND_LICENSE_KEY}
      - GEOIPUPDATE_EDITION_IDS=GeoLite2-City GeoLite2-Country GeoLite2-ASN
      - GEOIPUPDATE_FREQUENCY=24  # Update every 1 days (in hours)
```

### Default Configuration

Create `config.yaml` to manage your blocking rules.

In this default `config.yaml`, I have the following policies

* Country: `Mode: Whitelist` -> Only the allowed countries pass this check.  All else returns 403
* ASN: `Mode: Blacklist` -> All known datacenter ASNs are blacklisted from provided URL.  
  - Additional ASNs manually added to blacklist.  
  - ASNs can be added to the whitelist for exceptions (VPN provider)
  - ASNs can be added to the whitelist with specific user-agent requirements
* user-agent: `Mode: Blacklist` -> All known bot user-agents are blacklisted from provided URL
  - Additional user-agent values added to blakclist


```yaml
# Country Filtering
countries:
  mode: whitelist  # Options: whitelist, blacklist, disabled
  whitelist:
    - US  # United States
    - CA  # Canada
  blacklist: []

# ASN Filtering
asn:
  mode: blacklist  # Options: whitelist, blacklist, disabled
  
  # Whitelist can be used in two ways:
  # - In "whitelist" mode: Only these ASNs are allowed (strict mode)
  # - In "blacklist" mode: These ASNs are exceptions to the blacklist
  # whitelist:
  #   - 212238  # ProtonVPN - Fully trust an ASN
  #   # Trust an ASN only with specific user_agents
  #   - asn: 212238  # Datacamp (ProtonVPN)
  #     user_agents:
  #       - "Sonarr/*"      # *arr applications only
  #       - "Prowlarr/*"
  #       - "Lidarr/*"
  #       - "Radarr/*"
  
  # Fetch ASN lists from remote URLs (loaded at startup)
  blacklist_urls:
    - https://raw.githubusercontent.com/brianhama/bad-asn-list/refs/heads/master/only%20number.txt
  whitelist_urls: []
  
  # Manual ASN entries (combined with fetched lists)
  blacklist:
    - 16509   # AMAZON-02 (AWS)
    - 13335   # Cloudflare
    - 15169   # Google LLC
    # Add more ASNs with comments...

# User-Agent Filtering
user_agent:
  mode: blacklist  # Options: whitelist, blacklist, disabled
  
  # Fetch user-agent lists from remote URLs (loaded at startup)
  blacklist_urls:
    - https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-user-agents.list
  whitelist_urls: []
  
  # Manual user-agent entries (combined with fetched lists)
  # Uses substring matching (case-insensitive)
  blacklist:
    - "sqlmap"
    - "nikto"
    - "nmap"
    - "bot"
    - "crawler"
    - "python-requests"
  whitelist: []

# domains:
#   integration-api.example.com:
#     ip:
#       mode: whitelist
#       whitelist:
#         - "192.168.1.100"  # Home IP Only
```

## Features

- **Country-based blocking** (whitelist or blacklist)
- **ASN-based blocking** (whitelist or blacklist)
- **User-agent filtering** (blacklist with substring matching)
- **IP filtering** with literal IPs, **CIDR ranges**, and **hostnames/DDNS** (resolved with a TTL cache — a rotating residential IP keeps working without a config edit)
- Supports MaxMind GeoLite2 Country and ASN databases, **or a single combined IPinfo Lite database** (country + ASN in one file, updated daily, CC-BY-SA 4.0)
- Remote blocklist fetching with caching
- **Hot-reload** — edit `config.yaml` (or send `SIGHUP`) and new rules go live in ~2s with zero dropped requests; a malformed config never breaks the running service
- **Token-authed admin API** for runtime rule edits over HTTPS (agent-operable — no shell access needed)
- **Built-in web admin UI** (thin frontend over the admin API)
- **Config lint** — surfaces contradictions and footguns (e.g. an ASN in both lists, an overly broad user-agent substring)
- YAML configuration file with inline comments
- Private IP allowance option
- Health check endpoint (minimal by default; full summary behind the admin token)
- Detailed logging + an audit log for admin edits
- Configurable service port

![Screenshot](docs/images/country-block.png)

![Screenshot](docs/images/asn-block.png)

## Configuration

**ASN Mode Behavior:**
- **`whitelist` mode**: Only ASNs in whitelist are allowed (strict deny-by-default)
- **`blacklist` mode**: ASNs in blacklist are blocked, BUT whitelist entries are exceptions (useful for trusting specific VPNs/services while blocking all other datacenters)
- **`disabled` mode**: No ASN filtering


**Remote ASN Lists:**
- Lists are fetched at container startup and combined with manual entries
- **Caching**: Downloaded lists are cached for 168 hours (7 days) in `/blocklists` to avoid re-downloading on every restart
- **Local files**: Place custom ASN list files in `./geo-asn-auth/blocklists/` and reference them as `/blocklists/filename.txt`
- Supports any URL or file with one ASN per line (comments with `#` are ignored)
- Example: brianhama/bad-asn-list contains 1277+ datacenter/hosting ASNs
- Failed fetches are logged but don't prevent startup
- Manual entries are preserved and merged with remote lists

**User-Agent Lists:**
- User-agent blacklists/whitelists work the same way as ASN lists
- **Matching**: Uses substring matching (case-insensitive) - "bot" will match "MyBot/1.0" and "botnet"
- Example: mitchellkrogza list contains ~4000 known bad user-agents (scrapers, crawlers, scanners)
- **Performance**: Compiled regex patterns add ~0.3-0.5ms per request

**Example with local file:**
```bash
# Create custom ASN list
echo "12345" > ./geo-asn-auth/blocklists/my-custom-asns.txt
echo "67890" >> ./geo-asn-auth/blocklists/my-custom-asns.txt
```

```yaml
# In config.yaml:
blacklist_urls:
  - /blocklists/my-custom-asns.txt  # Local file
  - https://raw.githubusercontent.com/brianhama/bad-asn-list/refs/heads/master/only%20number.txt  # Remote (cached)
```

### Domain-Specific Overrides

You can override global settings for specific domains by adding a `domains:` section to your `config.yaml`. This is useful when different sites/APIs need different protection rules.

**Matching**: Domains are matched against the `Host` header. Supports exact matches and wildcards (`*.example.com`). The `Host` header is used because the fronting proxy pins it per-vhost, so a client can't forge it to reach a more-permissive domain config. If your proxy sets `X-Forwarded-Host` and you trust it, set `TRUST_FORWARDED_HOST=true` to prefer that header instead.

**Three Override Strategies:**

1. **REPLACE** (default) - Ignore global config, use only domain-specific settings
2. **PARTIAL OVERRIDE** - Override specific sections, inherit others
3. **EXTEND** - Merge with global config using `extend_global: true`

**Example: Admin Panel with IP Whitelist Only**
```yaml
domains:
  admin.example.com:
    ip:
      mode: whitelist
      whitelist:
        - "192.168.1.100"  # Office IP
        - "10.0.0.50"      # VPN IP
    countries:
      mode: disabled  # Don't check country
    asn:
      mode: disabled
    user_agent:
      mode: disabled
    settings:
      allow_lan: false  # Strict IP matching only
```

**Example: API with Different Country Rules**
```yaml
domains:
  api.example.com:
    countries:
      mode: blacklist  # Override just the country mode
      blacklist:
        - CN  # Block China
        - RU  # Block Russia
    # ASN and user_agent inherit from global config
```

**Example: Domain with Additional VPN Exceptions**
```yaml
domains:
  vpn-allowed.example.com:
    extend_global: true  # Merge instead of replace
    asn:
      whitelist:
        - 212238  # Add ProtonVPN to global whitelist
        - 9009    # Add another VPN
    # All other global settings still apply
```

**Example: Wildcard for All Subdomains**
```yaml
domains:
  *.internal.example.com:
    ip:
      mode: whitelist
      whitelist:
        - "10.0.0.0/8"  # Internal network only
    countries:
      mode: disabled
    asn:
      mode: disabled
```

### Environment Variables (docker-compose.yml)

Basic settings can be configured via environment:

```yaml
environment:
  - PORT=9876                      # Service port
  - ALLOW_LAN=true                 # Allow private/LAN IPs
  - ALLOW_UNKNOWN=true             # Allow when geo data unavailable
  - BLOCK_STATUS=403               # HTTP status on block: 403 (default) or 404
  - BLOCK_PAGE_PATH=/app/block_page.html  # Custom HTML block page (missing file -> JSON responses)
  - CACHE_HOURS=168                # Blocklist cache duration (default: 7 days)
  - CONFIG_PATH=/app/config.yaml
  - COUNTRY_DB_PATH=/data/GeoLite2-Country.mmdb
  - ASN_DB_PATH=/data/GeoLite2-ASN.mmdb
  - ADMIN_TOKEN=***           # Enables the admin API + web UI (unset = disabled)
  - DNS_TTL=60                     # TTL (s) for hostname/DDNS entries in IP lists
  - CONFIG_POLL_INTERVAL=2         # Config file poll interval (s) for hot-reload
  - BLOCKLIST_FETCH_TIMEOUT=10     # Per-URL blocklist fetch timeout (s)
  - BLOCKLIST_FETCH_BUDGET_S=15    # Total blocklist fetch budget per config load (s)
  - TRUST_FORWARDED_HOST=false     # If true, prefer X-Forwarded-Host over Host for domain matching (only if your proxy sets it)
  - AUDIT_LOG_PATH=/blocklists/audit.log  # Admin edit audit log location
  - ADMIN_FAIL_MAX=10              # Failed admin auth attempts per IP before 429
  - ADMIN_FAIL_MAX_IPS=1000        # Max tracked IPs in the auth-failure throttle
  - ADMIN_FAIL_WINDOW_S=60         # Sliding window (s) for the above
```

## Block Response

Blocked requests return **403** by default. Set `block_status: 404` (in `settings:`, or the `BLOCK_STATUS` env var) to return **404** instead — blocked clients then can't confirm the route exists, which many operators prefer for public-facing services. Only 403 and 404 are accepted; anything else fails config validation at startup rather than silently falling back.

The setting is per-domain overridable, like the other settings:

```yaml
settings:
  block_status: 403        # global default
domains:
  admin.example.com:
    settings:
      block_status: 404    # this domain hides blocked routes
```

The block page (HTML or JSON, see `use_html_response`) carries the configured status; the default HTML page is status-neutral ("Access Denied") so it works for either.

### Custom Block Page

The bundled page is a template, not hardcoded markup. Replace it wholesale by pointing at your own file:

```yaml
settings:
  block_page: /app/block_page.html   # or BLOCK_PAGE_PATH env var
```

or mount over the bundled file (no rebuild):

```yaml
volumes:
  - ./geoblock/block_page.html:/app/block_page.html:ro
```

Your HTML can use these placeholders (all HTML-escaped before insertion):

| Placeholder | Value |
|---|---|
| `{{reason}}` | Why the request was blocked |
| `{{client_ip}}` | Client IP (from X-Forwarded-For) |
| `{{country}}` | Country name — wrap in `{{#country}}...{{/country}}` to hide when unknown |
| `{{asn}}` | ASN — wrap in `{{#asn}}...{{/asn}}` to hide when unknown |
| `{{timestamp}}` | Block time (UTC) |
| `{{request_id}}` | Short ID matching the one in logs, for support lookups |

If the configured page is missing or unreadable, the service logs a warning and falls back to JSON block responses — it never fails to start over a missing page.

## Filtering Modes

- **whitelist**: Only allow specified countries/ASNs/user-agents (block all others)
- **blacklist**: Block specified countries/ASNs/user-agents (allow all others)
- **disabled**: Skip this check entirely

**Note**: For ASN blacklist mode, the whitelist acts as an exception list (e.g., trust specific VPNs while blocking all other datacenters).

## MaxMind Database Setup

1. Sign up for free MaxMind account: https://www.maxmind.com/en/geolite2/signup
2. Download GeoLite2 Country and ASN databases
3. Place `.mmdb` files in the directory you mount as `/data` in the container

## Reverse Proxy Integration

This service works as a ForwardAuth/External Authentication middleware for reverse proxies. **Every HTTP request** is processed by geo-asn-auth before reaching your application.

### Request Flow

1. Request arrives at reverse proxy
2. **geo-asn-auth** checks IP/user-agent against rules
3. If blocked: Returns 403 (request stops)
4. If allowed: Returns 200 (request continues to application)

---

## Traefik

### Step 1: Define the ForwardAuth middleware

Edit your Traefik dynamic configuration file (e.g., `dynamic_config.yml`):

```yaml
http:
  middlewares:
    geoblock:
      forwardAuth:
        address: http://geo-asn-auth:9876/verify
        trustForwardHeader: true
        authResponseHeaders:
          - X-Geo-Country
          - X-Geo-ASN
```

**Configuration details:**
- `address`: Must match your geo-asn-auth container name and port
- `trustForwardHeader`: Required to read `X-Forwarded-For` header
- `authResponseHeaders`: Optional headers passed to your application

### Step 2: Apply middleware globally or per-route

**Option A: Global (All Routes)**

Edit your Traefik static configuration file (e.g., `traefik_config.yml`):

```yaml
entryPoints:
  web:
    address: :80
  websecure:
    address: :443
    http:
      middlewares:
        - geoblock@file
```

This applies geo-asn-auth to **all HTTP/HTTPS traffic** at the entry point level.

**Option B: Per-Route**

Edit your dynamic configuration file:

```yaml
http:
  routers:
    my-app-router:
      rule: "Host(`example.com`)"
      entryPoints:
        - websecure
      middlewares:
        - geoblock  # Apply geo-asn-auth to this route only
        - security-headers
      service: my-app-service
      tls:
        certResolver: letsencrypt
```

### Step 3: Restart Traefik

```bash
docker compose restart traefik
```

### Verifying Integration

Check Traefik logs:

```bash
docker logs traefik | grep -i forward
```

Check geo-asn-auth logs:

```bash
docker logs geo-asn-auth
```

---

## Nginx

### Global Configuration (All Requests)

Edit your main Nginx configuration (e.g., `/etc/nginx/nginx.conf`):

```nginx
http {
    # Apply auth_request globally to all server blocks
    auth_request /auth;
    auth_request_set $auth_status $upstream_status;
    
    # Define the auth endpoint once
    location = /auth {
        internal;
        proxy_pass http://geo-asn-auth:9876/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Original-URI $request_uri;
    }
    
    # All server blocks now inherit auth_request automatically
    server {
        listen 80;
        server_name example.com;
        
        location / {
            proxy_pass http://backend:8080;
        }
    }
}
```

### Per-Server Configuration

If you only want to protect specific sites, place `auth_request` in individual server blocks:

```nginx
http {
    # Define auth endpoint in http block (shared)
    location = /auth {
        internal;
        proxy_pass http://geo-asn-auth:9876/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    # Protected server
    server {
        listen 80;
        server_name protected.com;
        
        auth_request /auth;  # Enable for this server only
        auth_request_set $auth_status $upstream_status;
        
        location / {
            proxy_pass http://backend:8080;
        }
    }
    
    # Unprotected server
    server {
        listen 80;
        server_name public.com;
        # No auth_request - this site is not protected
        
        location / {
            proxy_pass http://other-backend:8080;
        }
    }
}
```

### Disable for Specific Locations

Override globally-applied auth for specific paths:

```nginx
server {
    listen 80;
    server_name example.com;
    
    location / {
        # Inherits global auth_request
        proxy_pass http://backend:8080;
    }
    
    location /public {
        auth_request off;  # Disable auth for this path
        proxy_pass http://backend:8080;
    }
}
```

### Reload Nginx

```bash
nginx -t  # Test configuration
nginx -s reload  # Or: docker exec nginx nginx -s reload
```

---

## Caddy

### Global Configuration (All Sites)

Using a reusable snippet in your Caddyfile:

```caddyfile
# Define reusable snippet
(geoblock) {
    forward_auth geo-asn-auth:9876 {
        uri /verify
        copy_headers X-Geo-Country X-Geo-ASN
    }
}

# Apply to all sites
*.example.com {
    import geoblock
    reverse_proxy backend:8080
}

other-site.com {
    import geoblock
    reverse_proxy other-backend:8080
}
```

### Wildcard Global Application

Apply to all traffic using a catch-all:

```caddyfile
:80, :443 {
    forward_auth geo-asn-auth:9876 {
        uri /verify
        copy_headers X-Geo-Country X-Geo-ASN
    }
    
    @site1 host site1.com
    handle @site1 {
        reverse_proxy backend1:8080
    }
    
    @site2 host site2.com
    handle @site2 {
        reverse_proxy backend2:8080
    }
}
```

### Per-Site Configuration

Apply only to specific sites:

```caddyfile
# Protected site
protected.com {
    forward_auth geo-asn-auth:9876 {
        uri /verify
        copy_headers X-Geo-Country X-Geo-ASN
    }
    reverse_proxy backend:8080
}

# Unprotected site
public.com {
    # No forward_auth - not protected
    reverse_proxy other-backend:8080
}
```

### Reload Caddy

```bash
caddy reload  # Or: docker exec caddy caddy reload
```

---

## Endpoints

- `GET /verify` - ForwardAuth verification (used by Traefik)
- `GET /health` - Minimal health check (status + DB/reload state; reveals no rule contents)
- `GET /health/detail` - Full config summary (requires `ADMIN_TOKEN` Bearer auth)
- `GET /admin/config` - Current effective config + lint warnings (admin token)
- `GET|PUT /admin/{section}` - Read/edit a rule list (admin token). Sections: `ip-whitelist`, `ip-blacklist`, `asn-whitelist`, `asn-blacklist`, `country-whitelist`, `country-blacklist`, `user-agent-whitelist`, `user-agent-blacklist`
- `POST /admin/reload` - Force a config reload (admin token)
- `GET /admin/ui` - Built-in web admin UI (token entered in-browser)

## Hot-Reload

Config is watched continuously (mtime poll, ~2s) and reloaded on `SIGHUP`. Editing `config.yaml` makes new rules live within seconds **without restarting the container** — no dropped ForwardAuth requests.

- On a reload failure (malformed YAML, invalid mode), the service **keeps serving the last-good config** and logs the error. It never fails-open or crashes on a typo.
- If the config can't be loaded **at startup** (typo'd `CONFIG_PATH`, malformed YAML), the service starts **fail-closed**: every request is blocked, `/health` reports `degraded`, and it recovers automatically once the file is fixed (hot-reload, no restart). An allow-all fallback would turn a typo into an open door.
- `/health` reports `config_loaded` and `last_reload`; the reload error text (which can quote file paths) is behind `ADMIN_TOKEN` at `/health/detail`.
- Remote blocklists are only re-fetched when their cache expires (reload doesn't hammer blocklist URLs).

```bash
docker kill --signal=SIGHUP geo-asn-auth   # force an immediate reload
```

> Note: under the shipped gunicorn config (multiple workers), `docker kill --signal=SIGHUP` signals the gunicorn master, which does not forward SIGHUP to workers — the per-worker mtime poll is what actually reloads them (within `CONFIG_POLL_INTERVAL`). The poll path is the reliable one; SIGHUP is a convenience for single-process/dev runs.

## Admin API (runtime rule edits)

Set an `ADMIN_TOKEN` environment variable to enable the admin API. Without it, all `/admin/*` routes return 404 (fail closed). All admin calls use `Authorization: Bearer <ADMIN_TOKEN>`.

Generate a strong token — the API is a write path to your block rules:

```bash
openssl rand -hex 32
```

Failed auth attempts are throttled per-IP (default: 10 failures / 60s window, then `429` with `Retry-After`). Tune with `ADMIN_FAIL_MAX` and `ADMIN_FAIL_WINDOW_S`; this is a backstop, not a substitute for a strong token.

The write path is safe: **validate → auto-backup (`config.yaml.bak-<ts>`) → atomic write → hot-reload → audit log entry**. A failed reload rolls the file back.

> **Note:** admin edits re-serialize `config.yaml` — YAML comments and custom formatting are **not preserved**. If your config is comment-heavy, keep hand-editing it and use the admin API only when you don't mind the file being rewritten.

```bash
# Add a VPN ASN to the blacklist exception list, live in <5s:
curl -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"add": [212238]}' \
  http://localhost:9876/admin/asn-whitelist

# Remove an entry:
curl -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"remove": [9009]}' \
  http://localhost:9876/admin/asn-blacklist
```

This makes the blocker **agent-operable**: an AI assistant managing your homelab can whitelist the next rotating VPN ASN itself, over HTTPS, without shell access.

> **Security:** the admin paths must be excluded from your proxy's own ForwardAuth loop (or protected by a separate identity) to avoid auth recursion. Serve the UI on a management-only domain, never a public one. Edits are rate-limit-friendly but audited (`/blocklists/audit.log` by default, `AUDIT_LOG_PATH` to override).

## Web Admin UI

With `ADMIN_TOKEN` set, visit `/admin/ui` for a single-page dashboard: view modes and rule counts, add/remove IP, ASN (including conditional user-agent entries), country, and user-agent rules, with a diff-free validate-before-save. It is strictly a frontend over the admin API — there is no separate config-write path. Without `ADMIN_TOKEN` the page itself returns 404 (nothing to see, nothing to scan).

The UI rewrites `config.yaml` on save (with backup + rollback on failure), so YAML comments in the file are not preserved — the page shows this warning up front.

## Config Lint

On startup (and via `GET /admin/config`) the service lints its own config and logs warnings for contradictions and footguns:

- An ASN (or country/IP) present in **both** whitelist and blacklist
- Overly broad user-agent substrings like `bot`/`crawler` (substring match false-positives on e.g. "robot", "Abbott")
- A `whitelist` mode with an empty list (would block everything)

You can also lint a file without starting the service:

```bash
python -m src.config --lint /path/to/config.yaml
```

## Hostname / CIDR IP Entries

IP whitelist/blacklist entries accept three forms:

```yaml
ip:
  mode: whitelist
  whitelist:
    - "71.218.154.144"     # literal IP
    - "10.0.0.0/8"         # CIDR range
    - "home.example.com"   # DDNS hostname — resolved + cached (dns_ttl, default 60s)
```

A DDNS hostname means a rotating residential IP no longer requires a config edit to keep admin access. Set `settings.dns_ttl` to control the resolution cache.

## IPinfo Lite Provider

By default the service uses MaxMind GeoLite2 (separate Country + ASN databases). You can instead use a single combined **IPinfo Lite** database (country + ASN per record, updated daily, CC-BY-SA 4.0):

```bash
curl -L "https://ipinfo.io/data/ipinfo_lite.mmdb?token=$IPINFO_TOKEN" -o ipinfo_lite.mmdb
```

```yaml
geoip:
  provider: ipinfo-lite
  ipinfo_lite_db: /data/ipinfo_lite.mmdb
```

Mount the file into the container (e.g. `- ./config/maxmind:/data:ro`) and point `ipinfo_lite_db` at it. This replaces the two MaxMind files with one, simplifying the compose volume setup.

## Testing

Check health status:
```bash
curl http://localhost:9876/health
```

Test from specific IP (for testing, temporarily expose port):
```bash
curl -H "X-Forwarded-For: 8.8.8.8" http://localhost:9876/verify
```

Use the `maxmind-geoipupdate` container to keep databases current.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Support

- Report issues: https://github.com/WildeTechSolutions/geo-asn-auth/issues
- Questions: https://github.com/WildeTechSolutions/geo-asn-auth/discussions

## Logs

View logs:
```bash
docker logs -f geo-asn-auth
```

Logs show:
- Allowed/blocked requests with reason
- IP, country, and ASN information
- Configuration validation
- Database loading status
