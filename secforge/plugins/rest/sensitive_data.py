"""
Plugin: Sensitive Data Exposure / Excessive Data Exposure

Scans API responses for accidental leakage of:
1. Secret keys and credentials (AWS, GitHub, Stripe, private keys, JWT secrets)
2. PII (emails, phone numbers, SSNs, credit card numbers)
3. Internal infrastructure details (stack traces, DB strings, internal IPs)
4. Passwords or secrets embedded in JSON responses
5. Verbose error messages revealing implementation details

OWASP API Top 10: API3:2023 — Broken Object Property Level Authorization
                  (formerly API3:2019 — Excessive Data Exposure)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient


# ── Probe endpoints ───────────────────────────────────────────────────────────

PROBE_PATHS = [
    "/",
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v1/users",
    "/api/v1/users/me",
    "/api/v1/user",
    "/api/v1/profile",
    "/profile",
    "/api/v1/accounts",
    "/api/v1/orders",
    "/api/v1/config",
    "/api/v1/settings",
    "/health",
    "/status",
    "/debug",
    "/api/v1/debug",
    "/error",
    "/api/v1/products",
    "/api/v1/items",
]

# ── Detection rules ───────────────────────────────────────────────────────────

@dataclass
class LeakPattern:
    name:        str
    pattern:     re.Pattern
    severity:    str          # CRITICAL | HIGH | MEDIUM
    description: str
    remediation: str


LEAK_PATTERNS: list[LeakPattern] = [
    # ── Secret keys ──────────────────────────────────────────────────────────
    LeakPattern(
        name="AWS Access Key",
        pattern=re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
        severity="CRITICAL",
        description=(
            "An AWS Access Key ID was found in the API response. "
            "If paired with a secret key, an attacker gains full programmatic access "
            "to your AWS account — including S3 buckets, EC2 instances, and IAM."
        ),
        remediation=(
            "Immediately rotate the exposed key in the AWS IAM console. "
            "Use IAM roles instead of static key pairs. "
            "Store secrets in AWS Secrets Manager, not in code or API responses."
        ),
    ),
    LeakPattern(
        name="GitHub Personal Access Token",
        pattern=re.compile(r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}', re.IGNORECASE),
        severity="CRITICAL",
        description=(
            "A GitHub Personal Access Token was found in the API response. "
            "This grants read/write access to repositories, potentially exposing "
            "source code, secrets, and deployment configurations."
        ),
        remediation="Revoke the token at github.com/settings/tokens. Use fine-grained tokens with minimal scope.",
    ),
    LeakPattern(
        name="Stripe Secret Key",
        pattern=re.compile(r'sk_(live|test)_[A-Za-z0-9]{24,}', re.IGNORECASE),
        severity="CRITICAL",
        description=(
            "A Stripe secret key was found in the API response. "
            "This allows full access to charge customers, issue refunds, "
            "and retrieve payment method data."
        ),
        remediation="Roll the key immediately in the Stripe dashboard. Use restricted keys with only needed permissions.",
    ),
    LeakPattern(
        name="Private RSA/EC Key",
        pattern=re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----', re.IGNORECASE),
        severity="CRITICAL",
        description=(
            "A private cryptographic key was found in the API response. "
            "This could be an SSH key, TLS private key, or JWT signing key — "
            "allowing impersonation, decryption of traffic, or token forgery."
        ),
        remediation="Rotate all affected keys immediately. Remove private keys from application code and API responses.",
    ),
    LeakPattern(
        name="Generic High-Entropy Secret",
        pattern=re.compile(
            r'(?i)(?:password|passwd|secret|private_key|api_key|token)\s*[=:]\s*["\']?([A-Za-z0-9+/=_\-]{20,})["\']?',
        ),
        severity="HIGH",
        description=(
            "A JSON field or query parameter with a name suggesting a credential "
            "(password, secret, api_key, token) contains a non-empty value in the response. "
            "APIs should never return credential fields — even masked — in standard responses."
        ),
        remediation=(
            "Remove credential fields from API responses entirely. "
            "Use serialiser allowlists (not denylists) so only explicitly safe fields are returned. "
            "Return password hash indicators only where absolutely necessary (and never the hash itself)."
        ),
    ),
    # ── PII ──────────────────────────────────────────────────────────────────
    LeakPattern(
        name="Credit Card Number",
        pattern=re.compile(
            r'\b(?:4[0-9]{12}(?:[0-9]{3})?'          # Visa
            r'|5[1-5][0-9]{14}'                        # Mastercard
            r'|3[47][0-9]{13}'                         # Amex
            r'|6(?:011|5[0-9]{2})[0-9]{12})\b'        # Discover
        ),
        severity="CRITICAL",
        description=(
            "A pattern matching a credit card number (Visa, Mastercard, Amex, or Discover) "
            "was found in an API response. Exposing PANs violates PCI-DSS and can lead "
            "to significant regulatory fines and fraud liability."
        ),
        remediation=(
            "Never store or return full PANs. Truncate to last 4 digits in all responses. "
            "Use a PCI-compliant tokenisation provider (Stripe, Braintree) so raw card "
            "numbers never touch your servers."
        ),
    ),
    LeakPattern(
        name="US Social Security Number",
        pattern=re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        severity="CRITICAL",
        description=(
            "A pattern matching a US Social Security Number (SSN) was found in an API response. "
            "Exposure of SSNs is a severe HIPAA/PII violation and enables identity theft."
        ),
        remediation="Mask SSNs in all API responses. Return only last 4 digits where necessary.",
    ),
    LeakPattern(
        name="Email Address (Bulk Exposure)",
        pattern=re.compile(r'[a-zA-Z0-9._%+\-]{3,}@[a-zA-Z0-9.\-]{3,}\.[a-zA-Z]{2,}'),
        severity="MEDIUM",
        description=(
            "Email addresses were found in the API response. While a single user's own "
            "email in a /me endpoint is expected, bulk exposure of other users' emails "
            "enables spam, phishing, and account enumeration attacks."
        ),
        remediation=(
            "Audit which endpoints return email fields and to whom. "
            "Only return a user's own email after authentication. "
            "Never return email lists to non-admin callers."
        ),
    ),
    # ── Infrastructure leaks ─────────────────────────────────────────────────
    LeakPattern(
        name="Stack Trace in Response",
        pattern=re.compile(
            r'(Traceback \(most recent call last\)|'
            r'at [a-zA-Z0-9_$.]+\([a-zA-Z0-9_$.]+\.java:\d+\)|'
            r'System\.Exception:|'
            r'NullPointerException|'
            r'RuntimeError:|'
            r'sqlalchemy\.exc\.|'
            r'django\.core\.exceptions)',
            re.IGNORECASE,
        ),
        severity="HIGH",
        description=(
            "A server-side stack trace or framework exception was found in the API response. "
            "Stack traces reveal internal file paths, library versions, and code structure — "
            "dramatically reducing attacker reconnaissance effort."
        ),
        remediation=(
            "Catch all exceptions at the framework level and return generic error responses "
            "(e.g. HTTP 500 + error ID). Log stack traces server-side only. "
            "Set DEBUG=False in all production environments."
        ),
    ),
    LeakPattern(
        name="Database Connection String",
        pattern=re.compile(
            r'(?i)(postgres|mysql|mongodb|redis|mssql|sqlite)[+a-z]*://[^\s"\'<>]{10,}',
        ),
        severity="CRITICAL",
        description=(
            "A database connection string (including credentials) was found in the API response. "
            "This grants direct database access to anyone who receives the response."
        ),
        remediation=(
            "Remove all connection strings from application responses. "
            "Store DB credentials in environment variables or a secrets manager, "
            "never in code or serialised objects that reach the API layer."
        ),
    ),
    LeakPattern(
        name="Internal IP Address",
        pattern=re.compile(
            r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            r'|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
            r'|192\.168\.\d{1,3}\.\d{1,3}'
            r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        ),
        severity="MEDIUM",
        description=(
            "Internal RFC-1918 or loopback IP addresses were found in the API response. "
            "Leaking internal network topology assists attackers in planning lateral movement "
            "after initial access and can reveal SSRF probe targets."
        ),
        remediation=(
            "Sanitise error messages and response bodies to strip internal hostnames and IPs. "
            "Return public-facing hostnames or abstract service names only."
        ),
    ),
]


class SensitiveDataPlugin(BasePlugin):
    name = "sensitive_data"
    description = "Sensitive data & credential exposure — keys, PII, stack traces, DB strings"
    owasp_id = "API3:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        return await _scan_responses(target, client)


async def _scan_responses(target: TargetConfig, client: SecForgeClient) -> list[Finding]:
    findings: list[Finding] = []
    seen_titles: set[str] = set()  # Deduplicate across probed endpoints

    for path in PROBE_PATHS:
        try:
            resp = await client.get(path)
            if resp.status_code not in (200, 201, 400, 422, 500):
                continue

            body = _safe_text(resp)
            if not body:
                continue

            for rule in LEAK_PATTERNS:
                if rule.name in seen_titles:
                    continue

                matches = rule.pattern.findall(body)
                if not matches:
                    continue

                # For email, only flag if multiple unique addresses found (bulk exposure)
                if rule.name == "Email Address (Bulk Exposure)":
                    unique = set(m if isinstance(m, str) else m[0] for m in matches)
                    if len(unique) < 3:
                        continue
                    sample = ", ".join(list(unique)[:3])
                else:
                    raw = matches[0]
                    sample = raw if isinstance(raw, str) else raw[0] if raw else ""
                    sample = sample[:120]

                seen_titles.add(rule.name)

                sev_map = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH":     Severity.HIGH,
                    "MEDIUM":   Severity.MEDIUM,
                }
                severity = sev_map.get(rule.severity, Severity.MEDIUM)

                findings.append(Finding(
                    title=f"Sensitive Data Exposed: {rule.name}",
                    description=(
                        f"{rule.description}\n\n"
                        f"**Detected at:** `{path}`\n"
                        f"**Sample match:** `{sample}`"
                    ),
                    severity=severity,
                    status=FindingStatus.CONFIRMED,
                    owasp_id="API3:2023",
                    plugin="sensitive_data",
                    endpoint=path,
                    remediation=rule.remediation,
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
                    ],
                    evidence=[Evidence.from_httpx(
                        resp.request, resp,
                        note=f"Pattern [{rule.name}] matched in response body at {path}. Sample: {sample[:100]}",
                    )],
                ))

        except httpx.HTTPError:
            continue

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_text(resp: httpx.Response) -> str:
    try:
        return resp.text[:8000]
    except Exception:
        return ""
