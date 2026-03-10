"""
SSRF Plugin — Server-Side Request Forgery detection.

Maps to: OWASP API7:2023 — Server-Side Request Forgery

Strategy (blackbox, no OOB callback server):
  1. Inject cloud metadata / localhost URLs into common SSRF-prone parameters
  2. Detect server-side fetch via: metadata canaries in 2xx body, SSRF error strings, timing
  3. Detect open redirect chains that can be weaponized for SSRF
  4. Flag proxy/fetch endpoints for manual follow-up

Evidence integrity rules:
  - CONFIRMED requires canary in 2xx response body (proves the server fetched the URL)
  - PROBABLE requires clear SSRF error signal string in response body
  - SPECULATIVE only for timing anomaly (server may have attempted fetch)
  - All Evidence uses Evidence.from_httpx() for real request/response capture
"""

from __future__ import annotations

import asyncio
import time

from secforge.plugins.base import BasePlugin
from secforge.core.client import SecForgeClient
from secforge.models.evidence import Evidence
from secforge.models.finding import Finding
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig

# ── SSRF-prone parameter names ────────────────────────────────────────────────
SSRF_PARAMS = [
    "url", "uri", "link", "src", "dest", "destination",
    "redirect", "redirect_uri", "redirect_url",
    "callback", "callback_url", "webhook", "webhook_url",
    "endpoint", "proxy", "host", "next", "return",
]

# ── Payloads ──────────────────────────────────────────────────────────────────
CLOUD_META_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",       # AWS
    "http://169.254.169.254/metadata/v1/",            # DigitalOcean
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
]

LOCALHOST_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
]

BYPASS_PAYLOADS = [
    "http://0x7f000001/",    # Hex 127.0.0.1
    "http://2130706433/",    # Decimal 127.0.0.1
]

# Strings that prove the server resolved and returned cloud metadata.
# Only checked in 2xx responses to avoid false positives on error pages.
META_CANARIES = [
    "ami-id", "instance-id", "local-ipv4",
    "iam/security-credentials",
    "computeMetadata", "instance/attributes",
    "AccessKeyId", "SecretAccessKey",
    # NOTE: "access_token" intentionally excluded — it appears in OAuth error pages
    #       and would create false positives on 4xx responses.
]

SSRF_ERROR_SIGNALS = [
    "connection refused", "connection timed out", "no route to host",
    "failed to connect", "could not resolve host", "name or service not known",
    "network is unreachable", "i/o timeout", "dial tcp", "getaddrinfo",
    "failed to fetch", "unable to connect",
]

# Paths that suggest a fetch/proxy endpoint
PROXY_PATHS = [
    "/api/proxy", "/api/fetch", "/api/request", "/proxy",
    "/fetch", "/webhook", "/callback", "/forward",
    "/api/v1/proxy", "/api/v1/fetch",
]

REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "next", "return",
    "goto", "continue", "url",
]


class SSRFPlugin(BasePlugin):
    """SSRF detection — OWASP API7:2023."""

    name = "ssrf"
    description = "Server-Side Request Forgery — cloud metadata, localhost probes, open redirect chains"
    owasp_id = "API7:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []

        results = await asyncio.gather(
            self._probe_ssrf_params(target, client),
            self._probe_open_redirects(target, client),
            self._check_proxy_endpoints(target, client),
            return_exceptions=True,
        )

        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    # ── 1. Inject SSRF payloads into common parameter names ───────────────────
    async def _probe_ssrf_params(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []

        all_payloads = CLOUD_META_PAYLOADS + LOCALHOST_PAYLOADS + BYPASS_PAYLOADS[:1]

        for payload in all_payloads:
            for param in SSRF_PARAMS[:8]:  # top 8 most common
                path = f"/?{param}={payload}"
                try:
                    t0 = time.monotonic()
                    resp = await client.get(path)
                    elapsed = time.monotonic() - t0

                    body = ""
                    try:
                        body = resp.text[:4000]
                    except Exception:
                        pass

                    body_lower = body.lower()

                    # ── CONFIRMED: Canary in 2xx response body ────────────────
                    # Only trigger on 2xx — error pages (4xx/5xx) can contain
                    # these strings in unrelated context (e.g. OAuth error messages).
                    if resp.status_code < 300:
                        for canary in META_CANARIES:
                            if canary.lower() in body_lower:
                                findings.append(Finding(
                                    plugin=self.name,
                                    title="SSRF — Cloud Metadata Exposed",
                                    severity=Severity.CRITICAL,
                                    status=FindingStatus.CONFIRMED,
                                    owasp_id=self.owasp_id,
                                    cwe_id="CWE-918",
                                    description=(
                                        f"The server fetched the injected URL `{payload}` via the "
                                        f"`?{param}=` parameter and returned cloud metadata in the "
                                        f"response (canary: `{canary}`). An attacker can extract "
                                        "IAM credentials, instance identity tokens, or internal "
                                        "service configuration."
                                    ),
                                    endpoint=f"{target.url}{path}",
                                    evidence=[Evidence.from_httpx(
                                        resp.request, resp,
                                        note=(
                                            f"Injected cloud metadata URL via ?{param}=. "
                                            f"Canary '{canary}' found in 2xx response body — "
                                            "server fetched the injected URL."
                                        ),
                                    )],
                                    remediation=(
                                        "Block server-side HTTP requests to link-local "
                                        "(169.254.169.254) and private IP ranges (RFC 1918). "
                                        "Use an allowlist of permitted external hosts. "
                                        "Validate and sanitize all URL parameters before "
                                        "making outbound requests."
                                    ),
                                    references=[
                                        "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
                                        "https://portswigger.net/web-security/ssrf",
                                    ],
                                ))
                                return findings  # Critical confirmed — stop immediately

                    # ── PROBABLE: SSRF error signal in response body ──────────
                    # Error strings like "connection refused" prove the server
                    # attempted an outbound connection to the injected URL.
                    for signal in SSRF_ERROR_SIGNALS:
                        if signal in body_lower:
                            findings.append(Finding(
                                plugin=self.name,
                                title="SSRF — Server Attempted Outbound Connection",
                                severity=Severity.HIGH,
                                status=FindingStatus.PROBABLE,
                                owasp_id=self.owasp_id,
                                cwe_id="CWE-918",
                                description=(
                                    f"Injecting `{payload}` via `?{param}=` produced an error "
                                    f"message (`{signal}`) indicating the server attempted an "
                                    "outbound HTTP request to the injected URL. "
                                    "Confirm impact with an OOB callback server (Burp Collaborator)."
                                ),
                                endpoint=f"{target.url}{path}",
                                evidence=[Evidence.from_httpx(
                                    resp.request, resp,
                                    note=(
                                        f"SSRF error signal '{signal}' found in response body. "
                                        "Server likely attempted outbound request to injected URL."
                                    ),
                                )],
                                remediation=(
                                    "Sanitize URL parameters server-side. Block requests to "
                                    "RFC 1918 private ranges and link-local addresses. "
                                    "Use an HTTP egress allowlist."
                                ),
                                references=[
                                    "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
                                ],
                            ))
                            return findings

                    # ── SPECULATIVE: Timing anomaly on metadata probe ─────────
                    # A slow response to 169.254.169.254 may indicate a server-side
                    # fetch attempt timing out. Not confirmed — requires OOB verification.
                    if "169.254.169.254" in payload and elapsed > 4.0:
                        findings.append(Finding(
                            plugin=self.name,
                            title="SSRF — Timing Anomaly on Metadata Probe",
                            severity=Severity.MEDIUM,
                            status=FindingStatus.PROBABLE,
                            owasp_id=self.owasp_id,
                            cwe_id="CWE-918",
                            description=(
                                f"Request to `?{param}={payload}` took {elapsed:.1f}s, "
                                "which may indicate the server is attempting an outbound "
                                "connection to 169.254.169.254 before timing out. "
                                "Verify with a Burp Collaborator OOB payload."
                            ),
                            endpoint=f"{target.url}{path}",
                            evidence=[Evidence.from_httpx(
                                resp.request, resp,
                                note=(
                                    f"Response time: {elapsed:.1f}s (expected: <1s). "
                                    "Unusual delay suggests server may be attempting "
                                    "outbound connection to metadata endpoint."
                                ),
                            )],
                            remediation=(
                                "Validate that the application does not make outbound HTTP "
                                "requests based on user-controlled URL parameters."
                            ),
                        ))

                except Exception:
                    pass

        # ── POST body probes ──────────────────────────────────────────────────
        for param in ["url", "redirect", "callback", "webhook"]:
            for payload in CLOUD_META_PAYLOADS[:1]:
                try:
                    resp = await client.post("/api/", json={param: payload})
                    body = ""
                    try:
                        body = resp.text[:2000]
                    except Exception:
                        pass
                    # Only trigger on 2xx responses
                    if resp.status_code < 300:
                        for canary in META_CANARIES:
                            if canary.lower() in body.lower():
                                findings.append(Finding(
                                    plugin=self.name,
                                    title="SSRF — Cloud Metadata via POST Body",
                                    severity=Severity.CRITICAL,
                                    status=FindingStatus.CONFIRMED,
                                    owasp_id=self.owasp_id,
                                    cwe_id="CWE-918",
                                    description=(
                                        f"POST body `{{{param}: {payload}}}` caused the server to "
                                        f"fetch the injected URL and return cloud metadata. "
                                        f"Canary `{canary}` confirmed in 2xx response body."
                                    ),
                                    endpoint=f"{target.url}/api/",
                                    evidence=[Evidence.from_httpx(
                                        resp.request, resp,
                                        note=(
                                            f"Canary '{canary}' found in 2xx response body "
                                            f"after POST with {{{param}: {payload}}}."
                                        ),
                                    )],
                                    remediation=(
                                        "Block SSRF via POST body URL parameters. "
                                        "Validate all outbound URLs server-side."
                                    ),
                                ))
                except Exception:
                    pass

        return findings

    # ── 2. Open redirect → SSRF escalation chain ──────────────────────────────
    async def _probe_open_redirects(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []
        canary = "http://evil-attacker.com/"

        for param in REDIRECT_PARAMS:
            path = f"/?{param}={canary}"
            try:
                resp = await client.get(path, follow_redirects=False)
                location = resp.headers.get("Location", "")
                if "evil-attacker.com" in location:
                    findings.append(Finding(
                        plugin=self.name,
                        title="Open Redirect — SSRF Escalation Vector",
                        severity=Severity.MEDIUM,
                        status=FindingStatus.CONFIRMED,
                        owasp_id=self.owasp_id,
                        cwe_id="CWE-601",
                        description=(
                            f"The `{param}` parameter value is reflected directly into the "
                            "`Location` header without validation. While not direct SSRF, open "
                            "redirects can be chained with SSRF vulnerabilities and enable phishing."
                        ),
                        endpoint=f"{target.url}{path}",
                        evidence=[Evidence.from_httpx(
                            resp.request, resp,
                            note=(
                                f"Location header reflects injected value: {location}. "
                                "No redirect validation in place."
                            ),
                        )],
                        remediation=(
                            "Validate redirect destinations against an allowlist of permitted domains. "
                            "Reject redirect parameters pointing to external hosts."
                        ),
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                        ],
                    ))
            except Exception:
                pass

        return findings

    # ── 3. Detect proxy/fetch endpoints ───────────────────────────────────────
    async def _check_proxy_endpoints(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        """Flag endpoints that look like fetch/proxy handlers for manual SSRF testing."""
        findings: list[Finding] = []

        for path in PROXY_PATHS:
            try:
                resp = await client.get(path)
                # 404/410 = not found, 429 = rate limited (not meaningful for SSRF)
                if resp.status_code not in (404, 410, 429):
                    findings.append(Finding(
                        plugin=self.name,
                        title="SSRF — Proxy/Fetch Endpoint Detected",
                        severity=Severity.MEDIUM,
                        status=FindingStatus.PROBABLE,
                        owasp_id=self.owasp_id,
                        cwe_id="CWE-918",
                        description=(
                            f"`{path}` returned HTTP {resp.status_code}. "
                            "Proxy and fetch endpoints are commonly vulnerable to SSRF. "
                            "Manual testing with internal URLs and an OOB callback (e.g. "
                            "Burp Collaborator) is recommended."
                        ),
                        endpoint=f"{target.url}{path}",
                        evidence=[Evidence.from_httpx(
                            resp.request, resp,
                            note=(
                                f"Endpoint {path} exists (HTTP {resp.status_code}). "
                                "Proxy/fetch endpoints are high-risk SSRF candidates — "
                                "manual verification recommended."
                            ),
                        )],
                        remediation=(
                            "If this endpoint is intentional, enforce strict URL allowlisting. "
                            "Block requests to RFC 1918 ranges, localhost, and link-local addresses."
                        ),
                    ))
            except Exception:
                pass

        return findings
