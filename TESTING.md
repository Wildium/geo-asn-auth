# GeoBlock Service Testing

## Run Tests

Install development dependencies:
```bash
pip install -r requirements-dev.txt
```

Run all tests:
```bash
pytest tests/ -v
```

Run with coverage report:
```bash
pytest tests/ -v --cov=src --cov-report=html --cov-report=term
```

Run specific test class:
```bash
pytest tests/test_service.py::TestIPMatcher -v
```

Run specific test:
```bash
pytest tests/test_service.py::TestAdminAPI::test_put_add_asn_live_and_audited -v
```

## Test Coverage

The test suite (`tests/test_service.py`) covers:

### Configuration
- ✅ Loading from YAML files (modes, lists, settings, env overrides)
- ✅ Conditional ASN whitelist entries (per-user-agent rules)
- ✅ Invalid mode raises at load

### IP Matching (literal / CIDR / hostname)
- ✅ Literal IP matching
- ✅ CIDR ranges (IPv4 + IPv6)
- ✅ Hostname/DDNS entries via TTL-cached resolver
- ✅ Stale-on-DNS-failure behavior
- ✅ Invalid CIDR ignored

### Verification (ForwardAuth)
- ✅ IP blacklist/whitelist modes, whitelist bypass
- ✅ CIDR whitelist
- ✅ User-agent blacklist/whitelist
- ✅ Country whitelist/blacklist + unknown handling (allow/block)
- ✅ ASN blacklist with whitelist exception + conditional UA
- ✅ Fail-open on errors

### Domain Overrides
- ✅ Exact domain override (matchers rebuilt)
- ✅ Wildcard `*.example.com` matching (fnmatch regression)
- ✅ `extend_global` merge

### Hot-Reload
- ✅ File edit picked up without restart
- ✅ Malformed config keeps last-good + records error
- ✅ force_reload returns success bool

### Admin API
- ✅ No token → API disabled (404); bad token → 401
- ✅ GET section; PUT add/remove live + backup + audit
- ✅ Invalid edit rolls back

### Health
- ✅ /health reveals no rule contents
- ✅ /health/detail requires token

### Lint
- ✅ ASN overlap, broad UA substring, empty whitelist warnings
- ✅ lint-file CLI errors on bad mode

### IPinfo Lite Provider
- ✅ Country + ASN from one record
- ✅ Missing record raises; provider selection

## Docker Testing

Build and test in Docker:
```bash
cd /home/ubuntu/docker/pangolin
sudo docker compose build geoblock-service
sudo docker compose run --rm geoblock-service pytest /app/tests -v
```

## Continuous Integration

Tests are designed to work with GitHub Actions and can be integrated into CI/CD pipelines:

```yaml
- name: Run tests
  run: |
    pip install -r requirements-dev.txt
    pytest tests/ -v --cov=src --cov-report=xml
```

## Test Structure

Each test class focuses on a specific aspect:
- `TestConfigParsing` - Configuration loading and parsing
- `TestIPMatcher` - Literal/CIDR/hostname IP matching
- `TestVerification` - ForwardAuth filtering layers
- `TestDomainConfig` - Domain overrides + wildcards
- `TestHotReload` - Hot-reload safety
- `TestAdminAPI` - Token-authed runtime edits
- `TestHealth` - Health endpoints
- `TestLint` - Config hygiene
- `TestIPinfoLite` - Combined-DB provider

## Mocking Strategy

Tests use mocking to avoid requiring:
- Actual MaxMind database files
- Network access for remote ASN lists
- Real configuration files

This makes tests:
- Fast (no I/O)
- Reliable (no external dependencies)
- Portable (run anywhere)
