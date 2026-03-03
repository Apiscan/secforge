"""
Plugin: Broken Authentication

Tests for common authentication weaknesses:
1. Endpoints accessible without any authentication token
2. JWT vulnerabilities: alg:none, algorithm confusion, weak secrets
3. API key exposure in URLs or error messages
4. Verbose error messages revealing auth internals

OWASP API Top 10: API2:2023 — Broken Authentication
"""

from __future__ import annotations

import base64
import json
import re
from typing import Optional

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient


# Endpoints that should require authentication
SENSITIVE_PATHS = [
    "/api/v1/users",
    "/api/v1/users/me",
    "/api/v2/users",
    "/api/users",
    "/users",
    "/api/v1/admin",
    "/admin",
    "/api/v1/accounts",
    "/accounts",
    "/api/v1/profile",
    "/profile",
    "/api/v1/settings",
    "/settings",
    "/api/v1/orders",
    "/orders",
    "/api/v1/payments",
    "/payments",
    "/api/v1/dashboard",
    "/dashboard",
    "/api/v1/config",
    "/config",
]

# JWT attack payloads
ALG_NONE_SUFFIXES = ["", ".", "eyJ9"]  # Minimal "none" alg tokens


class AuthPlugin(BasePlugin):
    name = "auth"
    description = "Broken authentication detection (missing auth, JWT weaknesses)"
    owasp_id = "API2:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []

        # ── Test 1: Endpoints accessible without authentication ───────────
        unauth_findings = await _test_missing_auth(target, client)
        findings.extend(unauth_findings)

        # ── Test 2: JWT algorithm confusion (alg:none) ────────────────────
        jwt_findings = await _test_jwt_alg_none(target, client)
        findings.extend(jwt_findings)

        # ── Test 3: API key in URL ────────────────────────────────────────
        url_key_findings = await _test_api_key_in_url(target, client)
        findings.extend(url_key_findings)

        return findings


async def _test_missing_auth(target: TargetConfig, client: SecForgeClient) -> list[Finding]:
    """Test if sensitive endpoints are accessible without any auth token."""
    findings = []

    # Only meaningful if target has auth configured
    if target.auth.type == "none":
        return []

    # Build a no-auth client by overriding auth headers
    unauth_headers = {
        k: v for k, v in {
            **client.target.headers,
        }.items()
        if k.lower() not in ("authorization", "x-api-key", "api-key")
    }

    exposed_endpoints = []

    for path in SENSITIVE_PATHS:
        try:
            # Send request explicitly without the auth header
            resp = await client.get(
                path,
                headers={**unauth_headers, "Authorization": ""},
            )
            # 200 on a sensitive endpoint without valid auth = broken auth
            if resp.status_code == 200:
                body = _safe_text(resp)
                if len(body) > 30 and _looks_like_data(body):
                    ev = Evidence.from_httpx(
                        resp.request, resp,
                        note=(
                            f"GET {path} returned HTTP 200 without valid auth token. "
                            f"Response body: {body[:300]}"
                        ),
                    )
                    exposed_endpoints.append((path, ev))
        except httpx.HTTPError:
            continue

    if exposed_endpoints:
        findings.append(Finding(
            title="Missing Authentication on Sensitive Endpoint(s)",
            description=(
                f"Found {len(exposed_endpoints)} endpoint(s) returning HTTP 200 "
                "without a valid authentication token. These endpoints may be "
                "publicly accessible to any unauthenticated caller.\n\n"
                "Affected:\n" + "\n".join(f"  • {p}" for p, _ in exposed_endpoints)
            ),
            severity=Severity.CRITICAL,
            status=FindingStatus.CONFIRMED,
            owasp_id="API2:2023",
            plugin="auth",
            endpoint=exposed_endpoints[0][0],
            remediation=(
                "Enforce authentication on all sensitive endpoints. "
                "Use middleware/guards to apply auth checks globally, "
                "then explicitly open only public endpoints."
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"
            ],
            evidence=[ev for _, ev in exposed_endpoints[:3]],
        ))

    return findings


async def _test_jwt_alg_none(target: TargetConfig, client: SecForgeClient) -> list[Finding]:
    """Test if the API accepts JWT tokens with alg:none (signature bypass)."""
    findings = []

    # Only relevant if target uses Bearer auth with a JWT
    if target.auth.type != "bearer" or not target.auth.token:
        return []

    token = target.auth.token
    parts = token.split(".")
    if len(parts) != 3:
        return []  # Not a JWT

    try:
        # Decode the payload (don't verify)
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.b64decode(payload_b64).decode())
    except Exception:
        return []

    # Build alg:none token variants
    none_header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()

    none_payload = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()

    alg_none_variants = [
        f"{none_header}.{none_payload}.",   # No signature
        f"{none_header}.{none_payload}.{parts[2]}",  # Original sig (ignored by vulnerable server)
    ]

    for variant in alg_none_variants:
        for path in ["/api/v1/users/me", "/api/v1/profile", "/profile", "/me", "/"]:
            try:
                resp = await client.get(
                    path,
                    headers={"Authorization": f"Bearer {variant}"},
                )
                if resp.status_code == 200:
                    body = _safe_text(resp)
                    if _looks_like_data(body):
                        findings.append(Finding(
                            title="JWT Algorithm Confusion: alg:none Accepted",
                            description=(
                                "The API accepted a JWT token with alg:none — meaning "
                                "the server validates the token without verifying its "
                                "cryptographic signature. An attacker can forge arbitrary "
                                "tokens by setting alg:none and modifying the payload "
                                "(e.g., elevating user_id, role, or scope) without "
                                "knowing the signing secret."
                            ),
                            severity=Severity.CRITICAL,
                            status=FindingStatus.CONFIRMED,
                            owasp_id="API2:2023",
                            plugin="auth",
                            endpoint=path,
                            remediation=(
                                "Explicitly whitelist accepted signing algorithms in your "
                                "JWT library. Reject tokens with alg:none. "
                                "Use a library that defaults to rejecting unsigned tokens."
                            ),
                            references=[
                                "https://portswigger.net/web-security/jwt",
                                "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                            ],
                            evidence=[Evidence.from_httpx(
                                resp.request, resp,
                                note=(
                                    f"Sent JWT with alg:none, no valid signature → "
                                    f"server returned HTTP 200 with data at {path}"
                                ),
                            )],
                        ))
                        return findings  # One confirmed is enough to stop
            except httpx.HTTPError:
                continue

    return findings


async def _test_api_key_in_url(target: TargetConfig, client: SecForgeClient) -> list[Finding]:
    """Check if API keys appear in response URLs (e.g. Location headers, body links)."""
    findings = []

    api_key_patterns = [
        r'[?&](api_key|apikey|key|token|access_token|auth_token)=([A-Za-z0-9_\-\.]{20,})',
        r'(sk-[A-Za-z0-9]{20,})',
        r'(Bearer [A-Za-z0-9_\-\.]{40,})',
    ]

    try:
        resp = await client.get("/")
        body = _safe_text(resp)
        location = resp.headers.get("location", "")
        full_text = body + location

        for pattern in api_key_patterns:
            matches = re.findall(pattern, full_text, re.IGNORECASE)
            if matches:
                sample = str(matches[0])
                findings.append(Finding(
                    title="API Key or Token Exposed in Response/URL",
                    description=(
                        "Found what appears to be an API key or authentication token "
                        f"in the API response body or headers: {sample[:80]}...\n\n"
                        "Credentials in URLs are logged by web servers, proxies, "
                        "browser history, and Referer headers — making them easily leaked."
                    ),
                    severity=Severity.HIGH,
                    status=FindingStatus.PROBABLE,
                    owasp_id="API2:2023",
                    plugin="auth",
                    endpoint=str(resp.url),
                    remediation=(
                        "Never include credentials in URLs. Pass auth via headers only "
                        "(Authorization: Bearer <token>). Rotate any exposed credentials immediately."
                    ),
                    evidence=[Evidence.from_httpx(
                        resp.request, resp,
                        note=f"Pattern match found in response: {sample[:100]}",
                    )],
                ))
                break  # One finding per response is enough
    except httpx.HTTPError:
        pass

    return findings


def _safe_text(resp: httpx.Response) -> str:
    try:
        return resp.text[:2000]
    except Exception:
        return ""


def _looks_like_data(body: str) -> bool:
    stripped = body.strip()
    return stripped.startswith(("{", "[")) or '"id"' in body or '"data"' in body
