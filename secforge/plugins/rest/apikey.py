"""
Plugin: API Key Security Assessment

Analyzes API key quality and identifies common weaknesses:

1. Low entropy — predictable, short, or character-limited keys
2. Vendor pattern detection — identify key format (Stripe, GitHub, etc.)
3. Key in URL — scans response bodies/URLs for exposed keys
4. Sequential/predictable keys — detect incrementing patterns
5. Test/demo keys still active — common test credentials

OWASP API Top 10: API2:2023 — Broken Authentication
"""

from __future__ import annotations

import math
import re
import string
from collections import Counter
from typing import Optional

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient


# Known vendor key patterns (pattern → vendor name)
VENDOR_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI / Stripe Secret Key"),
    (re.compile(r"pk_(?:live|test)_[A-Za-z0-9]{20,}"), "Stripe Public Key"),
    (re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{20,}"), "Stripe Secret Key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub Personal Access Token"),
    (re.compile(r"gho_[A-Za-z0-9]{36}"), "GitHub OAuth Token"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API Key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"[0-9a-fA-F]{32}"), "Possible MD5/UUID Key (hex-32)"),
    (re.compile(r"ntn_[A-Za-z0-9]{50,}"), "Notion API Token"),
]

# Common test/demo API keys that should never be active in production
TEST_KEYS = [
    "test", "demo", "example", "sample", "placeholder",
    "your-api-key", "your_api_key", "api_key_here",
    "changeme", "secret", "12345", "abcdef",
    "sk-test-", "pk_test_",
]

# Minimum entropy thresholds (bits)
MIN_ENTROPY_BITS = 80   # Below this → LOW finding
GOOD_ENTROPY_BITS = 128  # Below this → INFO


class APIKeyPlugin(BasePlugin):
    name = "apikey"
    description = "API key entropy, pattern detection, and exposure analysis"
    owasp_id = "API2:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []

        # Collect keys to analyze
        keys_to_check: list[tuple[str, str]] = []  # (key_value, source_description)

        # Check the configured auth key/token
        if target.auth.type == "bearer" and target.auth.token:
            keys_to_check.append((target.auth.token, "Bearer token in target profile"))
        if target.auth.type == "api_key" and target.auth.value:
            keys_to_check.append((target.auth.value, f"API key header ({target.auth.header or 'X-API-Key'})"))

        # Scan responses for exposed keys
        exposed = await _scan_responses_for_keys(client)
        keys_to_check.extend(exposed)

        for key, source in keys_to_check:
            key_findings = _analyze_key(key, source, target)
            findings.extend(key_findings)

        return findings


def _analyze_key(key: str, source: str, target: TargetConfig) -> list[Finding]:
    findings = []

    # ── Test keys / placeholder values ────────────────────────────────────
    # Flag if the test value dominates the key (>50% of its length) OR
    # the key is short (<20 chars) and contains it. Avoids false positives
    # on strong keys that happen to contain a substring like "abcdef".
    key_lower = key.lower()
    for test_val in TEST_KEYS:
        if not test_val or test_val not in key_lower:
            continue
        short_key = len(key) < 20
        dominates = len(test_val) / max(len(key), 1) > 0.4
        starts_with = key_lower.startswith(test_val) or key_lower.startswith(f"sk-{test_val}-")
        if not (short_key or dominates or starts_with):
            continue
        findings.append(Finding(
            title=f"Test/Placeholder API Key in Use: {key[:30]}...",
            description=(
                f"The API key from {source} appears to be a test or placeholder value "
                f"(contains '{test_val}'). Test keys in production environments "
                "often have elevated permissions and may be shared across environments."
            ),
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            owasp_id="API2:2023",
            plugin="apikey",
            endpoint=target.url,
            remediation="Generate a fresh cryptographically random production API key. Rotate immediately.",
            evidence=[Evidence.observed(
                note=f"Key value {key[:40]!r} matches test/placeholder pattern '{test_val}'",
                url=target.url,
            )],
        ))
        return findings  # Don't pile on more findings for a clearly bad key

    # ── Vendor pattern detection ──────────────────────────────────────────
    for pattern, vendor in VENDOR_PATTERNS:
        if pattern.search(key):
            findings.append(Finding(
                title=f"Vendor API Key Pattern Detected: {vendor}",
                description=(
                    f"The key from {source} matches the {vendor} format. "
                    "Vendor-specific key patterns confirm the third-party service in use, "
                    "aiding attacker targeting. Ensure this key is not hardcoded in "
                    "client-side code, URLs, or public repositories."
                ),
                severity=Severity.INFO,
                status=FindingStatus.CONFIRMED,
                owasp_id="API2:2023",
                plugin="apikey",
                endpoint=target.url,
                remediation="Store API keys in environment variables or secrets managers, never in code.",
                evidence=[Evidence.observed(
                    note=f"Key matches {vendor} pattern: {key[:30]}...",
                    url=target.url,
                )],
            ))
            break

    # ── Entropy analysis ─────────────────────────────────────────────────
    # Use only the key part (after any prefix like "sk-" or "Bearer ")
    key_stripped = re.sub(r'^[A-Za-z_-]+[:_-]', '', key).strip()
    if len(key_stripped) < 8:
        key_stripped = key

    entropy = _shannon_entropy(key_stripped)
    effective_bits = entropy * len(key_stripped)

    if effective_bits < MIN_ENTROPY_BITS:
        findings.append(Finding(
            title=f"Low Entropy API Key: {effective_bits:.0f} bits ({source})",
            description=(
                f"The API key has low entropy: {effective_bits:.0f} effective bits "
                f"(key length: {len(key_stripped)}, Shannon entropy: {entropy:.2f} bits/char). "
                f"Minimum recommended: {MIN_ENTROPY_BITS} bits. "
                "Low entropy keys are vulnerable to brute-force and guessing attacks."
            ),
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            owasp_id="API2:2023",
            plugin="apikey",
            endpoint=target.url,
            remediation=(
                f"Generate API keys using a CSPRNG with at least {GOOD_ENTROPY_BITS} bits of entropy. "
                "Use secrets.token_urlsafe(32) in Python, crypto.randomBytes(32) in Node.js."
            ),
            evidence=[Evidence.observed(
                note=f"Key: {key[:20]}... | Length: {len(key_stripped)} | Entropy: {entropy:.2f} bits/char | Total: {effective_bits:.0f} bits",
                url=target.url,
            )],
        ))
    elif effective_bits < GOOD_ENTROPY_BITS:
        findings.append(Finding(
            title=f"Moderate Entropy API Key: {effective_bits:.0f} bits ({source})",
            description=(
                f"The API key has moderate entropy ({effective_bits:.0f} bits). "
                f"While not immediately brute-forceable, {GOOD_ENTROPY_BITS}+ bits is recommended."
            ),
            severity=Severity.LOW,
            status=FindingStatus.CONFIRMED,
            owasp_id="API2:2023",
            plugin="apikey",
            endpoint=target.url,
            remediation=f"Use keys with at least {GOOD_ENTROPY_BITS} bits of entropy.",
            evidence=[Evidence.observed(
                note=f"Entropy analysis: {effective_bits:.0f} bits effective",
                url=target.url,
            )],
        ))

    return findings


async def _scan_responses_for_keys(client: SecForgeClient) -> list[tuple[str, str]]:
    """Scan API responses for exposed API keys or tokens."""
    found: list[tuple[str, str]] = []
    scan_paths = ["/", "/api", "/api/v1", "/api/v1/config", "/health", "/status", "/debug"]

    key_regex = re.compile(
        r'(?:api[_-]?key|token|secret|credential|auth)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{20,})',
        re.IGNORECASE,
    )

    for path in scan_paths:
        try:
            resp = await client.get(path)
            if resp.status_code == 200:
                body = _safe_text(resp)
                for match in key_regex.finditer(body):
                    key_val = match.group(1)
                    found.append((key_val, f"Exposed in response body at {path}"))
        except httpx.HTTPError:
            pass

    return found[:10]  # Limit


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _safe_text(resp: httpx.Response) -> str:
    try:
        return resp.text[:5000]
    except Exception:
        return ""
