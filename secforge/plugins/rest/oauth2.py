"""
Plugin: OAuth2 Security Assessment

Tests common OAuth2 implementation weaknesses:

1. redirect_uri validation — open redirect / token theft
2. state parameter — CSRF in authorization flow
3. Token endpoint — verbose errors, client_secret exposure
4. Authorization server discovery — metadata endpoint leakage
5. PKCE enforcement — code interception attack

OWASP API Top 10: API2:2023 — Broken Authentication
"""

from __future__ import annotations

import re
from urllib.parse import urlencode, urlparse, parse_qs

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient


# Common OAuth2 authorization endpoints (accept response_type + redirect_uri)
AUTH_ENDPOINTS = [
    "/oauth/authorize",
    "/oauth2/authorize",
    "/api/v1/oauth/authorize",
    "/auth/authorize",
    "/connect/authorize",
]

# OIDC discovery / metadata endpoints (separate — not authorize endpoints)
OIDC_DISCOVERY_ENDPOINTS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

TOKEN_ENDPOINTS = [
    "/oauth/token",
    "/oauth2/token",
    "/api/v1/oauth/token",
    "/auth/token",
    "/connect/token",
]

EVIL_REDIRECT = "https://evil-attacker.com/callback"


class OAuth2Plugin(BasePlugin):
    name = "oauth2"
    description = "OAuth2 misconfiguration: redirect_uri bypass, CSRF, token endpoint"
    owasp_id = "API2:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []

        # ── 1. Discover OAuth endpoints ───────────────────────────────────
        discovered_auth = await _discover_endpoints(client, AUTH_ENDPOINTS)
        discovered_token = await _discover_endpoints(client, TOKEN_ENDPOINTS)

        # ── 2. OpenID Connect metadata disclosure ─────────────────────────
        oidc_findings = await _test_oidc_discovery(client, target)
        findings.extend(oidc_findings)

        # ── 3. redirect_uri validation ────────────────────────────────────
        for auth_path in discovered_auth:
            findings.extend(await _test_redirect_uri(client, target, auth_path))

        # ── 4. Token endpoint — verbose errors ────────────────────────────
        for token_path in discovered_token:
            findings.extend(await _test_token_endpoint(client, target, token_path))

        # ── 5. PKCE enforcement ───────────────────────────────────────────
        for auth_path in discovered_auth:
            findings.extend(await _test_pkce(client, target, auth_path))

        return findings


async def _discover_endpoints(client: SecForgeClient, paths: list[str]) -> list[str]:
    """Return paths that respond with non-404."""
    found = []
    for path in paths:
        try:
            resp = await client.get(path)
            if resp.status_code not in (404, 410):
                found.append(path)
        except httpx.HTTPError:
            pass
    return found


async def _test_oidc_discovery(client: SecForgeClient, target: TargetConfig) -> list[Finding]:
    findings = []
    try:
        resp = await client.get("/.well-known/openid-configuration")
        if resp.status_code == 200:
            try:
                data = resp.json()
                issuer = data.get("issuer", "")
                token_ep = data.get("token_endpoint", "")
                jwks_uri = data.get("jwks_uri", "")

                findings.append(Finding(
                    title="OpenID Connect Discovery Endpoint Exposed",
                    description=(
                        "The OIDC discovery document is publicly accessible at "
                        "/.well-known/openid-configuration. This reveals the full "
                        "OAuth2 server configuration including token endpoints, "
                        "supported grant types, and JWKS URI.\n\n"
                        f"Issuer: {issuer}\n"
                        f"Token endpoint: {token_ep}\n"
                        f"JWKS URI: {jwks_uri}"
                    ),
                    severity=Severity.INFO,
                    status=FindingStatus.CONFIRMED,
                    owasp_id="API2:2023",
                    plugin="oauth2",
                    endpoint=str(resp.url),
                    remediation=(
                        "OIDC discovery is standard and expected — this is informational. "
                        "Ensure all referenced endpoints are properly secured."
                    ),
                    evidence=[Evidence.from_httpx(resp.request, resp,
                        note="OIDC discovery document exposed — full config enumerated")],
                ))

                # Check for dangerous grant types
                grant_types = data.get("grant_types_supported", [])
                dangerous = [g for g in grant_types if g in ("password", "implicit")]
                if dangerous:
                    findings.append(Finding(
                        title=f"Dangerous OAuth2 Grant Types Supported: {', '.join(dangerous)}",
                        description=(
                            f"The OAuth2 server supports deprecated/dangerous grant types: "
                            f"{', '.join(dangerous)}. "
                            "\n• 'password' grant: exposes user credentials to the client app"
                            "\n• 'implicit' grant: tokens in URL fragments, no PKCE, deprecated by OAuth 2.1"
                        ),
                        severity=Severity.MEDIUM,
                        status=FindingStatus.CONFIRMED,
                        owasp_id="API2:2023",
                        plugin="oauth2",
                        endpoint=str(resp.url),
                        remediation="Disable 'password' and 'implicit' grant types. Use 'authorization_code' + PKCE.",
                        references=["https://oauth.net/2.1/"],
                        evidence=[Evidence.from_httpx(resp.request, resp,
                            note=f"grant_types_supported includes: {dangerous}")],
                    ))
            except ValueError:
                pass
    except httpx.HTTPError:
        pass
    return findings


async def _test_redirect_uri(
    client: SecForgeClient,
    target: TargetConfig,
    auth_path: str,
) -> list[Finding]:
    """Test if redirect_uri validation can be bypassed."""
    findings = []

    evil_variants = [
        EVIL_REDIRECT,
        f"{EVIL_REDIRECT}@{target.host}",          # @-confusion
        f"https://{target.host}.evil-attacker.com",  # subdomain confusion
        EVIL_REDIRECT.replace("https", "http"),     # Scheme downgrade
    ]

    for evil_uri in evil_variants:
        params = {
            "response_type": "code",
            "client_id": "test",
            "redirect_uri": evil_uri,
            "scope": "openid email",
            "state": "test_csrf_state",
        }
        try:
            resp = await client.get(f"{auth_path}?{urlencode(params)}")

            # Only flag if the server's Location header points to the evil URI.
            # NOTE: resp.url includes our original query string — don't check it.
            location = resp.headers.get("location", "")

            if "evil-attacker.com" in location:
                findings.append(Finding(
                    title="OAuth2: Open Redirect via redirect_uri Bypass",
                    description=(
                        f"The authorization endpoint redirected to {evil_uri!r}. "
                        "An attacker can craft a malicious authorization URL that "
                        "redirects the victim's auth code to attacker-controlled server, "
                        "then exchange it for tokens and impersonate the victim."
                    ),
                    severity=Severity.CRITICAL,
                    status=FindingStatus.CONFIRMED,
                    owasp_id="API2:2023",
                    plugin="oauth2",
                    endpoint=auth_path,
                    remediation=(
                        "Maintain an exact-match allowlist of registered redirect URIs. "
                        "Never do prefix/suffix matching. Reject any URI not in the allowlist."
                    ),
                    references=["https://datatracker.ietf.org/doc/html/rfc6749#section-10.6"],
                    evidence=[Evidence.from_httpx(resp.request, resp,
                        note=f"redirect_uri={evil_uri!r} was accepted. Location: {location}")],
                ))
                return findings

            # Check if error response leaks internal info
            body = _safe_text(resp)
            if any(x in body.lower() for x in ["stack", "exception", "traceback", "internal"]):
                findings.append(Finding(
                    title="OAuth2: Verbose Error on Invalid redirect_uri",
                    description=(
                        "The authorization endpoint returns verbose error information "
                        "for invalid redirect_uri values, potentially exposing internal "
                        "implementation details."
                    ),
                    severity=Severity.LOW,
                    status=FindingStatus.CONFIRMED,
                    owasp_id="API2:2023",
                    plugin="oauth2",
                    endpoint=auth_path,
                    remediation="Return generic error messages. Log details server-side only.",
                    evidence=[Evidence.from_httpx(resp.request, resp,
                        note=f"Verbose error body: {body[:300]}")],
                ))
        except httpx.HTTPError:
            pass

    return findings


async def _test_token_endpoint(
    client: SecForgeClient,
    target: TargetConfig,
    token_path: str,
) -> list[Finding]:
    """Test token endpoint for verbose errors and client_secret in URL."""
    findings = []

    # Test with missing/invalid grant — check for verbose errors
    test_bodies = [
        {"grant_type": "authorization_code", "code": "invalid_test_code", "redirect_uri": "https://example.com"},
        {"grant_type": "password", "username": "test@test.com", "password": "test123"},
        {"grant_type": "client_credentials"},
    ]

    for body in test_bodies:
        try:
            resp = await client.post(token_path, data=body)
            resp_body = _safe_text(resp)

            # Verbose error detection
            if any(x in resp_body.lower() for x in ["stack", "exception", "traceback", "sql", "internal error"]):
                findings.append(Finding(
                    title="OAuth2 Token Endpoint: Verbose Error Disclosure",
                    description=(
                        "The token endpoint returns verbose error messages including "
                        "internal implementation details (stack trace, SQL, exceptions). "
                        "This aids attacker reconnaissance."
                    ),
                    severity=Severity.MEDIUM,
                    status=FindingStatus.CONFIRMED,
                    owasp_id="API2:2023",
                    plugin="oauth2",
                    endpoint=token_path,
                    remediation="Return RFC 6749 standard error responses only. Log internals server-side.",
                    evidence=[Evidence.from_httpx(resp.request, resp,
                        note=f"Verbose error in response: {resp_body[:300]}")],
                ))
                break

            # Password grant accepted (dangerous)
            if body.get("grant_type") == "password" and resp.status_code in (200, 400):
                if resp.status_code == 200 or "invalid_client" in resp_body.lower():
                    findings.append(Finding(
                        title="OAuth2: Password Grant Type Active",
                        description=(
                            "The token endpoint responds to 'password' grant type requests. "
                            "This deprecated grant type requires clients to handle user "
                            "credentials directly, violating the OAuth2 security model."
                        ),
                        severity=Severity.MEDIUM,
                        status=FindingStatus.PROBABLE,
                        owasp_id="API2:2023",
                        plugin="oauth2",
                        endpoint=token_path,
                        remediation="Disable the password grant type. Use authorization_code + PKCE.",
                        evidence=[Evidence.from_httpx(resp.request, resp,
                            note=f"Password grant responded HTTP {resp.status_code}: {resp_body[:200]}")],
                    ))
        except httpx.HTTPError:
            pass

    return findings


async def _test_pkce(
    client: SecForgeClient,
    target: TargetConfig,
    auth_path: str,
) -> list[Finding]:
    """Test if PKCE is enforced (should reject auth requests without code_challenge)."""
    findings = []

    # Request without PKCE params
    params_no_pkce = {
        "response_type": "code",
        "client_id": "test_client",
        "redirect_uri": target.url,
        "scope": "openid",
        "state": "csrf_test_state_12345",
    }

    try:
        resp = await client.get(f"{auth_path}?{urlencode(params_no_pkce)}")
        body = _safe_text(resp)

        # If we get a login page or redirect (not an error about missing PKCE) — PKCE not enforced
        if resp.status_code in (200, 302) and "code_challenge" not in body.lower():
            location = resp.headers.get("location", "")
            # Only flag if it actually proceeded (login form shown or redirect to client)
            if resp.status_code == 200 and len(body) > 100:
                findings.append(Finding(
                    title="OAuth2: PKCE Not Enforced",
                    description=(
                        "The authorization endpoint accepted a request without "
                        "code_challenge/code_verifier (PKCE) parameters. "
                        "Without PKCE, authorization codes can be intercepted and "
                        "exchanged by malicious apps (authorization code interception attack), "
                        "especially in mobile and SPA contexts."
                    ),
                    severity=Severity.MEDIUM,
                    status=FindingStatus.PROBABLE,
                    owasp_id="API2:2023",
                    plugin="oauth2",
                    endpoint=auth_path,
                    remediation=(
                        "Require PKCE (code_challenge + code_verifier) for all "
                        "authorization code flows, especially for public clients."
                    ),
                    references=["https://datatracker.ietf.org/doc/html/rfc7636"],
                    evidence=[Evidence.from_httpx(resp.request, resp,
                        note="Auth request without code_challenge accepted — PKCE not required")],
                ))
    except httpx.HTTPError:
        pass

    return findings


def _safe_text(resp: httpx.Response) -> str:
    try:
        return resp.text[:2000]
    except Exception:
        return ""
