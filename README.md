# SecForge — API Security Scanner

<p align="center">
  <img src="https://img.shields.io/badge/OWASP_API_Top_10-10%2F10_Covered-00ff88?style=flat-square" />
  <img src="https://img.shields.io/badge/Python-3.10%2B-00f0ff?style=flat-square" />
  <img src="https://img.shields.io/badge/License-MIT-white?style=flat-square" />
  <img src="https://img.shields.io/badge/Scan_Time-under_15s-00ff88?style=flat-square" />
</p>

<p align="center">
  <strong>Find what attackers find. Before they do.</strong><br>
  CLI-native API security scanner with 11 security plugins and AI attack chain correlation.
</p>

<p align="center">
  <a href="https://app.apiscan.ai">Web App</a> · <a href="https://apiscan.ai">Docs</a> · <a href="https://apiscan.ai#pricing">Pricing</a>
</p>

---

## What makes SecForge different

Most security scanners tell you *"CORS is misconfigured."*

SecForge tells you: *"Your CORS misconfiguration + JWT signature bypass = an attacker can impersonate any user from a malicious webpage."*

That's the difference between a list of findings and an **attack chain** — the story of how vulnerabilities combine into a real exploit. That's what a senior pentester does after an engagement. SecForge does it automatically.

```
$ secforge scan --profile target.yaml --yes

  [tls]        ✓ PASS
  [headers]    ⚠ 2 missing headers (HSTS, CSP)
  [cors]       ✗ ARBITRARY ORIGIN REFLECTION
  [auth]       ✓ PASS
  [jwt]        ✗ ALG:NONE ACCEPTED
  [rate_limit] ✓ PASS
  [bola]       ✓ PASS
  [oauth2]     ✓ PASS
  [apikey]     ✓ PASS
  [graphql]    ✓ PASS
  [ssrf]       ✓ PASS

  ──────────────────────────────────────────────
  CRITICAL ATTACK CHAIN DETECTED
  CORS Reflection + JWT Algorithm None → Account Takeover

  Step 1: Attacker hosts malicious page at https://evil.com
  Step 2: CORS allows evil.com to make credentialed requests
  Step 3: JWT endpoint accepts alg:none — no signature required
  Step 4: Attacker crafts token for victim user ID, sends via CORS
  Result: Full authenticated API access as any user

  PoC: curl -H "Origin: https://evil.com" \
            -H "Authorization: Bearer eyJhbGciOiJub25lIn0..." \
            https://api.target.com/v1/users/profile
  ──────────────────────────────────────────────

  Scan complete: 2 findings (1 critical chain, 1 medium)
  Time: 11.3s
```

## Installation

```bash
pip install secforge

# Or from source
git clone https://github.com/your-org/secforge
cd secforge
pip install -e ".[dev]"
```

**Requirements:** Python 3.10+, no external dependencies at runtime.

## Quick Start

**1. Create a target profile:**

```yaml
# target.yaml
target:
  base_url: https://api.yourapp.com
  auth_header:
    Authorization: Bearer YOUR_TOKEN_HERE
  plugins: all
  scope_acknowledged: true  # required — confirms you have authorization
```

**2. Run the scan:**

```bash
secforge scan --profile target.yaml --yes
```

**3. Get a report:**

```bash
# Terminal output (default)
secforge scan --profile target.yaml --yes

# JSON report
secforge scan --profile target.yaml --yes --output report.json

# Markdown report
secforge scan --profile target.yaml --yes --output report.md --format markdown
```

## CI/CD Integration

```yaml
# .github/workflows/security.yml
- name: API Security Scan
  run: |
    pip install secforge
    secforge scan --profile .secforge/target.yaml --yes --output security-report.json
  env:
    API_TOKEN: ${{ secrets.API_TOKEN }}
```

## Plugins

All 11 plugins run in parallel. Every finding requires real HTTP evidence — no theoretical flags.

| Plugin | OWASP API | What It Tests |
|--------|-----------|---------------|
| `tls` | API8 | Protocol downgrade, cert expiry, self-signed, hostname mismatch, weak ciphers |
| `headers` | API8 | HSTS, CSP, X-Frame-Options, CORP, COEP, COOP — 6 required + 3 disclosure checks |
| `cors` | API8 | Arbitrary origin reflection, null origin bypass, subdomain prefix attacks |
| `bola` | API1 | Object-level auth bypass via sequential ID probing |
| `auth` | API2 | Missing auth on sensitive routes, JWT alg:none, API keys in URLs |
| `rate_limit` | API4 | Burst testing on root + auth endpoints, 429 detection, header validation |
| `jwt` | API2 | alg:none, RS256→HS256 confusion, weak key brute-force, kid injection, claim analysis |
| `oauth2` | API2 | redirect_uri bypass, dangerous grant types, PKCE enforcement, token endpoint verbosity |
| `apikey` | API2 | Entropy analysis, vendor pattern detection, test key flags, response scanning |
| `graphql` | API8 | Introspection, batching attacks, depth limits, field suggestions, GET mutation CSRF |
| `ssrf` | API7 | Cloud metadata probes (AWS/GCP/DO), localhost injection, open redirect chains |

## Severity Levels

| Level | Meaning |
|-------|---------|
| `CRITICAL` | Actively exploitable, immediate risk to data or system integrity |
| `HIGH` | Exploitable with moderate effort, significant risk |
| `MEDIUM` | Exploitable under specific conditions |
| `LOW` | Defense-in-depth issue, low direct risk |
| `INFO` | Best practice recommendation |

## Target Profile Reference

```yaml
target:
  base_url: https://api.yourapp.com    # required
  auth_header:                          # optional — adds auth to all requests
    Authorization: Bearer TOKEN
  plugins: all                          # all | [tls, cors, jwt] | comma-separated
  rate_limit_rps: 10                    # requests per second (default: 10)
  timeout_s: 30                         # request timeout (default: 30)
  scope_acknowledged: true              # REQUIRED — you confirm authorization
```

## Output Format

JSON report structure:

```json
{
  "target": "https://api.yourapp.com",
  "scan_time_s": 11.3,
  "findings": [
    {
      "plugin": "cors",
      "title": "Arbitrary Origin Reflection",
      "severity": "HIGH",
      "status": "CONFIRMED",
      "description": "The API reflects arbitrary origins with credentials.",
      "evidence": [
        {
          "request": "GET /api/v1/users HTTP/1.1\nOrigin: https://attacker.com",
          "response_status": 200,
          "response_headers": {
            "Access-Control-Allow-Origin": "https://attacker.com",
            "Access-Control-Allow-Credentials": "true"
          }
        }
      ],
      "remediation": "Implement an allowlist of trusted origins. Never reflect the Origin header directly."
    }
  ],
  "summary": { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 0, "INFO": 0 }
}
```

## Writing a Custom Plugin

```python
from secforge.plugins.base import BasePlugin, Finding, Severity, Status, Evidence

class MyPlugin(BasePlugin):
    name = "my_plugin"
    description = "Tests for something specific"

    async def run(self) -> list[Finding]:
        findings = []

        resp = await self.client.get("/api/sensitive")

        if resp.status_code == 200 and not self.client.headers.get("Authorization"):
            findings.append(Finding(
                plugin=self.name,
                title="Unauthenticated Access to Sensitive Endpoint",
                severity=Severity.HIGH,
                status=Status.CONFIRMED,
                description="The endpoint returned 200 without authentication.",
                evidence=[Evidence(
                    request=str(resp.request),
                    response_status=resp.status_code,
                )],
                remediation="Add authentication middleware to this route."
            ))

        return findings
```

## Ethics & Legal

**You must only scan systems you own or have explicit written authorization to test.**

SecForge enforces this via the `scope_acknowledged: true` flag in your target profile and the `--yes` CLI flag. Unauthorized scanning is illegal under computer crime laws in most jurisdictions.

The authors take no responsibility for misuse.

## AI Chain Analysis

The SaaS version at [app.apiscan.ai](https://app.apiscan.ai) adds a multi-stage AI analysis pipeline that:
- Removes false positives and re-classifies severity in context
- Verifies exploitability and generates PoC curl commands
- Correlates findings into multi-step attack chains
- Writes an executive summary with business impact

Free tier: 5 scans/month, 3 plugins.
Pro ($39/mo): all 11 plugins, full AI chain, 50 scans/month.

## Contributing

Pull requests welcome. For new plugins, see the [plugin development guide](#writing-a-custom-plugin) above.

Please include:
- A test using `respx` mocks (see `tests/` for examples)
- Evidence requirement documentation (what constitutes a CONFIRMED finding)
- Remediation guidance

## License

MIT — CLI and plugins are free and open source.

The AI chain analysis pipeline is proprietary and available via [app.apiscan.ai](https://app.apiscan.ai).

---

<p align="center">
  Built by <a href="https://apiscan.ai">SecForge</a> · <a href="https://app.apiscan.ai">Free scan</a> · <a href="https://apiscan.ai#pricing">Pricing</a>
</p>
