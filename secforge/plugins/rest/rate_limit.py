"""
Plugin: Rate Limiting — Unrestricted Resource Consumption

Tests whether the API enforces rate limiting to prevent abuse,
brute force, and resource exhaustion attacks.

Without rate limiting:
- Auth endpoints become brute-forceable
- Expensive API operations can be abused for DoS
- Data enumeration at scale becomes trivial

OWASP API Top 10: API4:2023 — Unrestricted Resource Consumption
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient


# Burst test config
BURST_COUNT = 15       # Number of rapid requests
BURST_ENDPOINT = "/"   # Default test endpoint
RATE_LIMIT_STATUS = {429, 503, 509}  # Status codes indicating rate limiting

# Auth endpoints are highest risk if not rate-limited
AUTH_PATHS = [
    "/api/v1/auth/login",
    "/api/v1/auth/signin",
    "/api/v1/login",
    "/api/auth/login",
    "/auth/login",
    "/login",
    "/api/v1/token",
    "/oauth/token",
    "/api/v1/auth/token",
]

RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-rate-limit-limit",
    "ratelimit-limit",
    "ratelimit-remaining",
    "retry-after",
    "x-ratelimit-policy",
]


class RateLimitPlugin(BasePlugin):
    name = "rate_limit"
    description = "Rate limiting and resource consumption detection"
    owasp_id = "API4:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []

        # ── Test 1: Burst test on root endpoint ───────────────────────────
        root_result = await _burst_test(client, BURST_ENDPOINT, BURST_COUNT)
        # Skip if rate-limit headers present — server has rate limiting, burst just didn't exceed it
        if not root_result["rate_limited"] and not root_result["has_rl_headers"]:
            findings.append(_build_finding(
                endpoint=BURST_ENDPOINT,
                full_url=f"{target.url}{BURST_ENDPOINT}",
                burst_count=BURST_COUNT,
                status_codes=root_result["statuses"],
                has_headers=root_result["has_rl_headers"],
                evidence=root_result["evidence"],
            ))

        # ── Test 2: Auth endpoint burst (higher severity) ─────────────────
        for auth_path in AUTH_PATHS:
            result = await _burst_test(client, auth_path, BURST_COUNT)
            if not result["status_codes_seen"]:
                continue  # All requests failed (connection error) — endpoint unreachable
            if result["status_codes_seen"] == {404}:
                continue  # Endpoint doesn't exist
            if not result["rate_limited"] and 404 not in result["status_codes_seen"]:
                ev = result["evidence"]
                ev.note = (
                    f"AUTH ENDPOINT: Sent {BURST_COUNT} rapid login requests to {auth_path} "
                    f"with no rate limiting response. This endpoint is brute-forceable. "
                    f"Status codes seen: {result['statuses']}"
                )
                findings.append(Finding(
                    title=f"No Rate Limiting on Authentication Endpoint: {auth_path}",
                    description=(
                        f"The authentication endpoint {auth_path} does not enforce "
                        f"rate limiting. Sent {BURST_COUNT} rapid requests with no "
                        "throttling response (HTTP 429 or Retry-After header). "
                        "This endpoint is vulnerable to credential brute-force and "
                        "credential stuffing attacks."
                    ),
                    severity=Severity.HIGH,
                    status=FindingStatus.CONFIRMED,
                    owasp_id=self.owasp_id,
                    plugin=self.name,
                    endpoint=auth_path,
                    remediation=(
                        "Implement strict rate limiting on all authentication endpoints: "
                        "5-10 attempts per IP per minute, exponential backoff, "
                        "and account lockout after repeated failures. "
                        "Consider CAPTCHA for repeated failed attempts."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                    ],
                    evidence=[ev],
                ))
                break  # One auth finding is enough

        return findings


def _build_finding(
    endpoint: str,
    full_url: str,
    burst_count: int,
    status_codes: str,
    has_headers: bool,
    evidence: Evidence,
) -> Finding:
    severity = Severity.MEDIUM
    header_note = "" if has_headers else " No rate-limit headers (X-RateLimit-*, Retry-After) were detected."

    return Finding(
        title=f"No Rate Limiting Detected on {endpoint}",
        description=(
            f"Sent {burst_count} rapid consecutive requests to {full_url} "
            f"with no rate limiting response (HTTP 429 or Retry-After header)."
            f"{header_note}\n\n"
            "Without rate limiting, the API is vulnerable to:\n"
            "  • Brute-force attacks on auth endpoints\n"
            "  • Data scraping and mass enumeration\n"
            "  • Resource exhaustion / DoS via expensive operations"
        ),
        severity=severity,
        status=FindingStatus.CONFIRMED,
        owasp_id="API4:2023",
        plugin="rate_limit",
        endpoint=endpoint,
        remediation=(
            "Implement rate limiting at the API gateway or application layer. "
            "Return HTTP 429 with a Retry-After header when limits are exceeded. "
            "Recommended: 60-100 req/min for general endpoints, "
            "5-10 req/min for auth endpoints."
        ),
        references=[
            "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
        ],
        evidence=[evidence],
    )


async def _burst_test(
    client: SecForgeClient,
    path: str,
    count: int,
) -> dict:
    """
    Fire `count` requests as fast as possible (bypassing our own rate limiter).
    Returns dict with: rate_limited, statuses, has_rl_headers, evidence, status_codes_seen
    """
    statuses = []
    has_rl_headers = False
    last_resp = None
    last_req = None
    status_codes_seen = set()

    # Bypass our own rate limiter for this test by using httpx directly
    try:
        async with httpx.AsyncClient(
            base_url=client.base_url,
            headers=dict(client._client.headers) if client._client else {},
            timeout=httpx.Timeout(10),
            verify=client.target.options.verify_ssl,
        ) as raw_client:
            tasks = [raw_client.get(path) for _ in range(count)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

        for r in responses:
            if isinstance(r, Exception):
                continue
            statuses.append(r.status_code)
            status_codes_seen.add(r.status_code)
            last_resp = r
            last_req = r.request

            # Check for rate limit headers
            for h in RATE_LIMIT_HEADERS:
                if h in {k.lower() for k in r.headers}:
                    has_rl_headers = True

    except Exception as e:
        return {
            "rate_limited": False,
            "statuses": str(e),
            "has_rl_headers": False,
            "status_codes_seen": set(),
            "evidence": Evidence.observed(f"Burst test failed: {e}", url=path),
        }

    rate_limited = bool(status_codes_seen & RATE_LIMIT_STATUS)
    statuses_str = f"{len(statuses)} requests → status codes: {sorted(status_codes_seen)}"

    evidence = Evidence.from_httpx(
        last_req, last_resp,
        note=(
            f"Burst: sent {count} rapid requests to {path}. {statuses_str}. "
            + ("Rate limiting headers present." if has_rl_headers else "No rate-limit headers detected.")
        ),
    ) if last_resp else Evidence.observed(
        note=f"Burst test completed. {statuses_str}",
        url=path,
    )

    return {
        "rate_limited": rate_limited,
        "statuses": statuses_str,
        "has_rl_headers": has_rl_headers,
        "status_codes_seen": status_codes_seen,
        "evidence": evidence,
    }
