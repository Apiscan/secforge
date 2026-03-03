"""
Plugin: HTTP Security Headers

Checks for presence and correctness of security-relevant HTTP response headers.
Missing or misconfigured headers are a common API8 (Security Misconfiguration) issue.

OWASP API Top 10: API8:2023 — Security Misconfiguration
"""

from __future__ import annotations

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient


# Header requirements: (header_name, expected_values_or_None, severity, description, remediation)
REQUIRED_HEADERS: list[dict] = [
    {
        "header": "Strict-Transport-Security",
        "check": lambda v: "max-age=" in v.lower(),
        "severity": Severity.HIGH,
        "title": "Missing HSTS Header",
        "description": (
            "The Strict-Transport-Security (HSTS) header is absent. "
            "This allows browsers and clients to connect over HTTP, enabling "
            "downgrade attacks and man-in-the-middle interception."
        ),
        "remediation": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
        "owasp_id": "API8:2023",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
        ],
        "https_only": True,  # Only relevant for HTTPS targets
    },
    {
        "header": "X-Content-Type-Options",
        "check": lambda v: "nosniff" in v.lower(),
        "severity": Severity.MEDIUM,
        "title": "Missing X-Content-Type-Options Header",
        "description": (
            "X-Content-Type-Options: nosniff is absent. Without it, browsers may "
            "MIME-sniff responses away from the declared Content-Type, potentially "
            "executing uploaded content as scripts."
        ),
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "owasp_id": "API8:2023",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
        ],
        "https_only": False,
    },
    {
        "header": "X-Frame-Options",
        "check": lambda v: any(x in v.upper() for x in ["DENY", "SAMEORIGIN"]),
        "severity": Severity.MEDIUM,
        "title": "Missing X-Frame-Options Header",
        "description": (
            "X-Frame-Options is absent. The API responses may be embeddable in iframes, "
            "enabling clickjacking attacks if the API serves any UI or auth flows."
        ),
        "remediation": "Add: X-Frame-Options: DENY",
        "owasp_id": "API8:2023",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
        ],
        "https_only": False,
    },
    {
        "header": "Content-Security-Policy",
        "check": lambda v: len(v) > 0,
        "severity": Severity.MEDIUM,
        "title": "Missing Content-Security-Policy Header",
        "description": (
            "No Content-Security-Policy (CSP) header found. CSP prevents XSS by "
            "controlling which resources the browser is allowed to load."
        ),
        "remediation": (
            "Add a CSP appropriate for your API. Minimum: "
            "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'"
        ),
        "owasp_id": "API8:2023",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"
        ],
        "https_only": False,
    },
    {
        "header": "Referrer-Policy",
        "check": lambda v: len(v) > 0,
        "severity": Severity.LOW,
        "title": "Missing Referrer-Policy Header",
        "description": (
            "Referrer-Policy is not set. Sensitive URLs or tokens in query strings "
            "may leak via the Referer header to third-party resources."
        ),
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "owasp_id": "API8:2023",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
        ],
        "https_only": False,
    },
    {
        "header": "Permissions-Policy",
        "check": lambda v: len(v) > 0,
        "severity": Severity.LOW,
        "title": "Missing Permissions-Policy Header",
        "description": (
            "Permissions-Policy (formerly Feature-Policy) is absent. "
            "Without it, the browser may grant the page access to sensitive "
            "features like geolocation, camera, and microphone."
        ),
        "remediation": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "owasp_id": "API8:2023",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
        ],
        "https_only": False,
    },
]

# Headers that reveal too much — check for their presence (presence = bad)
DISCLOSURE_HEADERS: list[dict] = [
    {
        "header": "Server",
        "severity": Severity.INFO,
        "title": "Server Version Disclosure",
        "description": (
            "The Server header reveals the web server software and/or version. "
            "This information helps attackers target known CVEs."
        ),
        "remediation": "Remove or genericize the Server header (e.g., Server: nginx).",
    },
    {
        "header": "X-Powered-By",
        "severity": Severity.LOW,
        "title": "Technology Disclosure via X-Powered-By",
        "description": (
            "X-Powered-By header reveals the application framework "
            "(e.g., Express, PHP, ASP.NET). Aids attacker fingerprinting."
        ),
        "remediation": "Remove the X-Powered-By header entirely.",
    },
    {
        "header": "X-AspNet-Version",
        "severity": Severity.LOW,
        "title": "ASP.NET Version Disclosure",
        "description": "X-AspNet-Version header exposes the exact .NET framework version.",
        "remediation": "Disable in web.config: <httpRuntime enableVersionHeader='false'/>",
    },
]


class HeadersPlugin(BasePlugin):
    name = "headers"
    description = "HTTP security headers assessment"
    owasp_id = "API8:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []

        try:
            response = await client.get("/")
        except httpx.HTTPError as e:
            # Try target URL directly if base / fails
            try:
                response = await client.get("")
            except httpx.HTTPError:
                return [Finding(
                    title="Headers Check — Connection Failed",
                    description=f"Could not connect to {target.url}: {e}",
                    severity=Severity.INFO,
                    status=FindingStatus.CONFIRMED,
                    plugin=self.name,
                    evidence=[Evidence.observed(f"Connection error: {e}", url=target.url)],
                )]

        resp_headers = {k.lower(): v for k, v in response.headers.items()}

        # Check required security headers
        for spec in REQUIRED_HEADERS:
            if spec.get("https_only") and not target.is_https:
                continue

            header_name = spec["header"].lower()
            value = resp_headers.get(header_name, "")

            if not value or not spec["check"](value):
                evidence = Evidence.from_httpx(
                    response.request,
                    response,
                    note=f"Header '{spec['header']}' is {'absent' if not value else f'present but misconfigured: {value!r}'}",
                )
                findings.append(Finding(
                    title=spec["title"],
                    description=spec["description"],
                    severity=spec["severity"],
                    status=FindingStatus.CONFIRMED,
                    owasp_id=spec.get("owasp_id"),
                    plugin=self.name,
                    endpoint=str(response.url),
                    remediation=spec["remediation"],
                    references=spec.get("references", []),
                    evidence=[evidence],
                ))

        # Check disclosure headers — only flag if value contains version info
        for spec in DISCLOSURE_HEADERS:
            header_name = spec["header"].lower()
            value = resp_headers.get(header_name, "")
            # For Server header: only flag if it contains a version number
            if header_name == "server" and value and not any(c.isdigit() for c in value):
                continue  # e.g. "nginx" alone is acceptable; "nginx/1.24.0" is not
            if value:
                evidence = Evidence.from_httpx(
                    response.request,
                    response,
                    note=f"Header '{spec['header']}' present with value: {value!r}",
                )
                findings.append(Finding(
                    title=spec["title"],
                    description=f"{spec['description']} Observed value: `{value}`",
                    severity=spec["severity"],
                    status=FindingStatus.CONFIRMED,
                    plugin=self.name,
                    endpoint=str(response.url),
                    remediation=spec["remediation"],
                    evidence=[evidence],
                ))

        return findings
