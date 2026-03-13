"""
Plugin: Unsafe Consumption of APIs

OWASP API10:2023 — Trusting external/third-party API data without validation.

Modern APIs don't run in isolation — they call payment processors, identity
providers, shipping APIs, AI services, and internal microservices. If any
of those return malicious data that your API reflects without sanitization,
the attacker controls your API from a distance.

Detection strategy:
──────────────────────────────────────────────────────────────────────────────
1. OPEN REDIRECT CHAINS
   Endpoints with redirect parameters that forward to attacker-controlled URLs.
   Can be chained with SSRF for internal service access.

2. REFLECTED EXTERNAL URL CONTENT
   Endpoints that fetch a URL from the request body and reflect its content
   back — server becomes a proxy for attacker-controlled content.

3. WEBHOOK SSRF VECTOR
   API webhook registration endpoints that accept attacker-controlled URLs
   and make server-side requests — indirect SSRF via trusted business flow.

4. THIRD-PARTY DATA INJECTION POINTS
   Endpoints that accept a URL/reference to external data and embed it in
   response — possible template injection, stored XSS, or data poisoning.

5. UNVALIDATED REDIRECT AFTER OAUTH / SSO
   OAuth2 redirect_uri parameters that accept arbitrary domains — token theft.
──────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient


# ── Open redirect parameter names ─────────────────────────────────────────────
REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return_url", "return",
    "next", "continue", "target", "goto", "url", "link", "forward",
    "destination", "dest", "ref", "callback", "callback_url",
    "success_url", "cancel_url", "post_login_redirect",
]

# ── Webhook / external URL parameter names ────────────────────────────────────
WEBHOOK_PARAMS = [
    "webhook_url", "webhook", "callback_url", "callback",
    "notify_url", "notification_url", "event_url", "endpoint",
    "target_url", "fetch_url", "import_url", "source_url",
]

# ── External URL fetch endpoint patterns ──────────────────────────────────────
FETCH_PATHS = [
    "/api/import", "/api/v1/import",
    "/api/fetch", "/api/v1/fetch",
    "/api/proxy", "/api/v1/proxy",
    "/api/preview", "/api/link-preview",
    "/api/export", "/api/upload/url",
    "/api/webhook", "/api/webhooks",
    "/api/v1/webhook", "/api/v1/webhooks",
    "/api/notifications/test",
    "/api/integrations",
]

# Open redirect test payload — should be blocked or stay on same origin
REDIRECT_TEST_URL = "https://evil.apiscan.ai/redirect-check"

# Reflected content canary — if the server fetches our URL, we'd see this in response
# We use a public endpoint known to return identifiable content
FETCH_CANARY_URL = "https://httpbin.org/get"
FETCH_CANARY_STRING = '"url": "https://httpbin.org/get"'


class UnsafeConsumptionPlugin(BasePlugin):
    name = "unsafe_consumption"
    description = "Unsafe consumption of APIs — open redirects, webhook SSRF, unvalidated external data"
    owasp_id = "API10:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []
        base = target.url.rstrip("/")

        auth_headers = {}
        if hasattr(target, "auth") and target.auth:
            try:
                from secforge.core.auth import build_auth_header
                ah = build_auth_header(target.auth)
                if ah:
                    auth_headers.update(ah)
            except Exception:
                pass

        async with httpx.AsyncClient(
            headers={
                "User-Agent": "ApiScan-SecurityScanner/1.0",
                **auth_headers,
            },
            timeout=12.0,
            follow_redirects=False,  # We want to see redirect targets, not follow them
            verify=False,
        ) as http:
            tasks = [
                self._check_open_redirects(http, base, findings),
                self._check_webhook_ssrf(http, base, findings),
                self._check_url_fetch_endpoints(http, base, findings),
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        return findings

    # ── Check 1: Open redirect via GET parameters ─────────────────────────────

    async def _check_open_redirects(
        self,
        http: httpx.AsyncClient,
        base: str,
        findings: list[Finding],
    ) -> None:
        """Test GET parameters that look like redirect targets."""
        # Common redirect-triggering paths
        redirect_paths = [
            "/login", "/signin", "/auth/login", "/api/auth/callback",
            "/logout", "/redirect", "/out", "/go", "/link",
            "/api/redirect", "/sso/callback", "/oauth/callback",
        ]

        for path in redirect_paths:
            for param in REDIRECT_PARAMS:
                url = f"{base}{path}?{param}={REDIRECT_TEST_URL}"
                try:
                    r = await http.get(url)
                    if r.status_code in (301, 302, 303, 307, 308):
                        location = r.headers.get("location", "")
                        if "evil.apiscan.ai" in location or REDIRECT_TEST_URL in location:
                            findings.append(Finding(
                                title=f"Open Redirect — {path}?{param}=",
                                description=(
                                    f"The `{path}` endpoint follows the `{param}` parameter to an "
                                    f"arbitrary external URL without validation. "
                                    f"The server responded with HTTP {r.status_code} and "
                                    f"`Location: {location}`.\n\n"
                                    f"**Impact**: Phishing attacks using a trusted domain. "
                                    f"OAuth token theft when combined with redirect_uri manipulation. "
                                    f"SSRF pivot if the redirect is followed server-side."
                                ),
                                severity=Severity.HIGH,
                                status=FindingStatus.CONFIRMED,
                                owasp_id=self.owasp_id,
                                plugin=self.name,
                                endpoint=url,
                                remediation=(
                                    f"Never use user-supplied URLs as redirect destinations. "
                                    f"Use an allowlist of approved redirect targets, or use "
                                    f"path-only redirects (e.g., /dashboard instead of full URL). "
                                    f"If external redirects are required, implement a signed token "
                                    f"that encodes the permitted destination."
                                ),
                                references=[
                                    "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
                                    "https://cwe.mitre.org/data/definitions/601.html",
                                ],
                                evidence=[Evidence(
                                    request_method="GET",
                                    request_url=url,
                                    response_status=r.status_code,
                                    response_headers=dict(r.headers),
                                    response_body_snippet=r.text[:200],
                                    note=f"HTTP {r.status_code} → Location: {location} — attacker-controlled redirect confirmed",
                                )],
                            ))
                            return  # One open redirect finding is sufficient
                except Exception:
                    continue

    # ── Check 2: Webhook / URL fetch SSRF ────────────────────────────────────

    async def _check_webhook_ssrf(
        self,
        http: httpx.AsyncClient,
        base: str,
        findings: list[Finding],
    ) -> None:
        """Check webhook registration endpoints for SSRF via user-supplied URLs."""
        # Internal URL that should never be fetched
        internal_urls = [
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://localhost/api/internal",
            "http://127.0.0.1/admin",
        ]

        for path in FETCH_PATHS:
            url = base + path
            for internal_url in internal_urls:
                for param in WEBHOOK_PARAMS:
                    # Try JSON body
                    payload = {param: internal_url, "url": internal_url}
                    try:
                        r = await http.post(
                            url,
                            json=payload,
                            headers={"Content-Type": "application/json"},
                        )
                        if r.status_code in (404, 405):
                            continue

                        body = r.text.lower()
                        # Signs the server attempted to fetch the URL
                        ssrf_signals = [
                            "metadata", "ami-id", "instance-id",
                            "connection refused", "timeout", "could not connect",
                            "no route to host", "name or service not known",
                        ]
                        got_signal = any(s in body for s in ssrf_signals)

                        if r.status_code in (200, 201) and (
                            "metadata" in body or "ami-id" in body
                        ):
                            # Server fetched cloud metadata — confirmed SSRF
                            findings.append(Finding(
                                title=f"Webhook SSRF — Internal URL Fetch Confirmed ({path})",
                                description=(
                                    f"The `{path}` endpoint accepted a webhook URL pointing to "
                                    f"an internal/cloud-metadata address and returned content from it. "
                                    f"The server fetched `{internal_url}` and exposed the result.\n\n"
                                    f"**Impact**: Full SSRF — can be used to access cloud provider "
                                    f"metadata (IAM credentials, instance data), internal services, "
                                    f"and pivot into the private network."
                                ),
                                severity=Severity.CRITICAL,
                                status=FindingStatus.CONFIRMED,
                                owasp_id=self.owasp_id,
                                plugin=self.name,
                                endpoint=url,
                                remediation=(
                                    "Validate all user-supplied webhook URLs against an allowlist. "
                                    "Block all private IP ranges (RFC1918, 169.254.0.0/16, ::1) "
                                    "before making outbound requests. "
                                    "Use a dedicated outbound proxy that enforces the allowlist. "
                                    "Never reflect the response of a webhook test back to the user."
                                ),
                                references=[
                                    "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
                                    "https://cwe.mitre.org/data/definitions/918.html",
                                ],
                                evidence=[Evidence(
                                    request_method="POST",
                                    request_url=url,
                                    request_body=str(payload),
                                    response_status=r.status_code,
                                    response_body_snippet=r.text[:500],
                                    note=f"Server fetched internal URL {internal_url} and reflected content",
                                )],
                            ))
                            return

                        if got_signal and r.status_code not in (422, 400):
                            findings.append(Finding(
                                title=f"Webhook SSRF Possible — Internal URL Accepted ({path})",
                                description=(
                                    f"The `{path}` endpoint accepted a webhook URL targeting "
                                    f"an internal address (`{internal_url}`) and the response "
                                    f"contains signals suggesting an outbound connection was attempted.\n\n"
                                    f"**Impact**: Potential SSRF — server-side requests to internal "
                                    f"infrastructure. Manual verification recommended."
                                ),
                                severity=Severity.HIGH,
                                status=FindingStatus.PROBABLE,
                                owasp_id=self.owasp_id,
                                plugin=self.name,
                                endpoint=url,
                                remediation=(
                                    "Validate all user-supplied URLs before making outbound requests. "
                                    "Block RFC1918 and link-local address ranges. "
                                    "Use a separate outbound proxy with allowlisting."
                                ),
                                references=[
                                    "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
                                ],
                                evidence=[Evidence(
                                    request_method="POST",
                                    request_url=url,
                                    request_body=str(payload),
                                    response_status=r.status_code,
                                    response_body_snippet=r.text[:400],
                                    note="SSRF signal in response — possible internal URL fetch",
                                )],
                            ))
                            return
                    except Exception:
                        continue

    # ── Check 3: URL fetch / import endpoints ─────────────────────────────────

    async def _check_url_fetch_endpoints(
        self,
        http: httpx.AsyncClient,
        base: str,
        findings: list[Finding],
    ) -> None:
        """Check for endpoints that fetch external URLs and reflect content."""
        for path in FETCH_PATHS:
            url = base + path
            # Try to register a webhook/import pointing at a known public endpoint
            for param in ["url", "fetch_url", "import_url", "source", "source_url", "link"]:
                payload = {param: FETCH_CANARY_URL}
                try:
                    r = await http.post(url, json=payload, headers={"Content-Type": "application/json"})
                    if r.status_code in (404, 405):
                        break  # endpoint doesn't exist
                    if r.status_code in (200, 201) and FETCH_CANARY_STRING in r.text:
                        # Server fetched our URL and reflected the content
                        findings.append(Finding(
                            title=f"Unvalidated External URL Fetch — {path}",
                            description=(
                                f"The `{path}` endpoint fetches a user-supplied URL and reflects "
                                f"the content in its response. Sending `{param}=https://httpbin.org/get` "
                                f"caused the server to fetch that URL and include its content in the "
                                f"HTTP {r.status_code} response.\n\n"
                                f"**Impact**: Can be combined with an internal URL to achieve SSRF. "
                                f"Enables content injection if the external data is not sanitized "
                                f"before being stored or returned to other users."
                            ),
                            severity=Severity.HIGH,
                            status=FindingStatus.CONFIRMED,
                            owasp_id=self.owasp_id,
                            plugin=self.name,
                            endpoint=url,
                            remediation=(
                                "Validate all external URLs before fetching: "
                                "(1) Allowlist permitted domains. "
                                "(2) Block RFC1918 and cloud metadata IPs after DNS resolution. "
                                "(3) Never reflect the raw response body back to the user. "
                                "(4) Sanitize any external data before storing or rendering."
                            ),
                            references=[
                                "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
                                "https://cwe.mitre.org/data/definitions/918.html",
                            ],
                            evidence=[Evidence(
                                request_method="POST",
                                request_url=url,
                                request_body=str(payload),
                                response_status=r.status_code,
                                response_body_snippet=r.text[:500],
                                note=f"Server fetched {FETCH_CANARY_URL} and reflected response body",
                            )],
                        ))
                        break
                except Exception:
                    continue
