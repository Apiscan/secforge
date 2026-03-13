"""
Plugin: Improper Inventory Management

OWASP API9:2023 — Outdated API versions, undocumented endpoints, and
shadow APIs that bypass security controls present in the current version.

Real-world scenario: Company launches v2 with auth fixes. v1 is never
retired. Attackers use v1 to bypass auth, access deprecated admin APIs,
or reach internal debugging endpoints that were never decommissioned.

Detection strategy:
──────────────────────────────────────────────────────────────────────────────
1. OLD API VERSION DETECTION
   Test /v1, /v2 alongside the active version — older versions often have
   weaker auth, missing rate limits, or deleted-but-not-removed endpoints.

2. VERSION SECURITY REGRESSION
   If /api/v1/users returns data without auth but /api/v2/users requires auth
   → v1 is a live auth bypass.

3. NON-PRODUCTION ENVIRONMENT EXPOSURE
   /staging/, /dev/, /test/, /sandbox/ accessible on production domain.
   Staging environments routinely skip security controls.

4. UNDOCUMENTED INTERNAL ENDPOINTS
   /internal/, /private/, /backend/, /service/ — not in docs, not secured.

5. ABANDONED API DOCUMENTATION
   /swagger-ui, /api-docs, /redoc accessible in production → exposes full
   schema, which makes targeted attacks far easier.
──────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient


# ── API version probe paths ──────────────────────────────────────────────────

# Probed against every detected auth-required endpoint
VERSION_PREFIXES = ["/v1", "/v2", "/v3", "/v4", "/api/v1", "/api/v2", "/api/v3"]

# Endpoints that should require auth — used to detect auth regression in old versions
AUTH_SENSITIVE_ENDPOINTS = [
    "/users", "/me", "/profile", "/accounts", "/admin",
    "/orders", "/payments", "/invoices", "/settings",
]

# Non-production paths
NON_PROD_PATHS = [
    "/staging",    "/dev",       "/development", "/test",
    "/testing",    "/sandbox",   "/qa",          "/uat",
    "/beta",       "/preview",   "/canary",      "/preprod",
    "/api/staging","/api/dev",   "/api/test",    "/api/sandbox",
]

# Internal / undocumented paths
INTERNAL_PATHS = [
    "/internal",          "/internal/api",
    "/private",           "/private/api",
    "/backend",           "/service",
    "/services",          "/micro",
    "/microservice",      "/gateway",
    "/api/internal",      "/api/private",
    "/api/backend",       "/api/service",
    "/_internal",         "/_admin",
    "/_api",              "/hidden",
    "/api/hidden",        "/api/secret",
]

# API documentation paths
DOC_PATHS = [
    "/swagger-ui",        "/swagger-ui.html",  "/swagger-ui/index.html",
    "/swagger",           "/swagger.json",     "/swagger.yaml",
    "/api-docs",          "/api-docs.json",    "/api/docs",
    "/openapi.json",      "/openapi.yaml",     "/openapi",
    "/redoc",             "/redoc.html",
    "/docs",              "/api/swagger",
    "/api/openapi",       "/api/openapi.json",
    "/v2/api-docs",       "/v3/api-docs",
]

# Strings in response that indicate doc endpoint is active
DOC_INDICATORS = [
    "swagger", "openapi", "redoc", "api-docs",
    '"paths":', '"openapi":', '"swagger":', '"info":', '"definitions":',
]


class InventoryPlugin(BasePlugin):
    name = "inventory"
    description = "Improper inventory management — old API versions, shadow APIs, non-prod exposure"
    owasp_id = "API9:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []
        base = target.url.rstrip("/")
        parsed = urlparse(base)
        # Strip existing version prefix to detect the current version
        current_version = self._detect_version(parsed.path)

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
            headers={"User-Agent": "ApiScan-SecurityScanner/1.0"},
            timeout=10.0,
            follow_redirects=True,
            verify=False,
        ) as http:
            tasks = [
                self._check_old_versions(http, base, current_version, auth_headers, findings),
                self._check_non_prod_exposure(http, base, findings),
                self._check_internal_paths(http, base, findings),
                self._check_doc_exposure(http, base, findings),
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        return findings

    def _detect_version(self, path: str) -> str | None:
        """Extract version number from URL path like /api/v2/..."""
        m = re.search(r"/v(\d+)(?:/|$)", path)
        return m.group(1) if m else None

    def _strip_to_base(self, base: str) -> str:
        """Remove /vN/ prefix to get the root base URL."""
        return re.sub(r"/v\d+(/.*)?$", "", base)

    # ── Check 1: Old API version auth regression ──────────────────────────────

    async def _check_old_versions(
        self,
        http: httpx.AsyncClient,
        base: str,
        current_version: str | None,
        auth_headers: dict,
        findings: list[Finding],
    ) -> None:
        """Test older version prefixes for auth regression."""
        root = self._strip_to_base(base)
        reported_versions: set[str] = set()

        for version_prefix in VERSION_PREFIXES:
            ver_num = re.search(r"v(\d+)", version_prefix)
            if not ver_num:
                continue
            # Don't probe the current version
            if current_version and ver_num.group(1) == current_version:
                continue
            if version_prefix in reported_versions:
                continue

            for sensitive_path in AUTH_SENSITIVE_ENDPOINTS:
                url = root + version_prefix + sensitive_path
                try:
                    # First: request WITH auth — if it returns 200, the endpoint exists
                    r_auth = await http.get(url, headers=auth_headers)
                    if r_auth.status_code not in (200, 201):
                        continue

                    # Endpoint exists. Now probe WITHOUT auth.
                    r_noauth = await http.get(url)  # no auth headers

                    if r_noauth.status_code in (200, 201, 206):
                        # Old version returns data without auth — regression!
                        reported_versions.add(version_prefix)
                        findings.append(Finding(
                            title=f"Old API Version Auth Bypass — {version_prefix}",
                            description=(
                                f"The deprecated API version `{version_prefix}` endpoint "
                                f"`{version_prefix}{sensitive_path}` returns data (HTTP {r_noauth.status_code}) "
                                f"without authentication, while the current version correctly requires auth.\n\n"
                                f"**Impact**: Attackers can use the old version to bypass authentication "
                                f"controls added in newer versions. Data at `{version_prefix}{sensitive_path}` "
                                f"is accessible to unauthenticated users."
                            ),
                            severity=Severity.CRITICAL,
                            status=FindingStatus.CONFIRMED,
                            owasp_id=self.owasp_id,
                            plugin=self.name,
                            endpoint=url,
                            remediation=(
                                f"Decommission `{version_prefix}` immediately if it is no longer supported. "
                                f"If it must remain live, ensure ALL security controls (auth, rate limiting, "
                                f"input validation) match the current version. "
                                f"Never retire security controls while keeping the endpoint alive."
                            ),
                            references=[
                                "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"
                            ],
                            evidence=[
                                Evidence(
                                    request_method="GET",
                                    request_url=url,
                                    response_status=r_noauth.status_code,
                                    response_body_snippet=r_noauth.text[:400],
                                    note=f"Unauthenticated request to {version_prefix}{sensitive_path} → HTTP {r_noauth.status_code} (data returned without auth)",
                                ),
                            ],
                        ))
                        break  # one finding per version prefix is enough

                    elif r_noauth.status_code not in (401, 403):
                        # Exists but returns unexpected status — flag as PROBABLE
                        reported_versions.add(version_prefix)
                        findings.append(Finding(
                            title=f"Old API Version Still Accessible — {version_prefix}",
                            description=(
                                f"The deprecated API version `{version_prefix}` is still reachable "
                                f"at `{version_prefix}{sensitive_path}` (HTTP {r_noauth.status_code}). "
                                f"Old versions commonly lack security controls added to newer versions.\n\n"
                                f"**Impact**: Reduced attack surface is a security baseline. "
                                f"Each additional live version is an additional attack surface."
                            ),
                            severity=Severity.MEDIUM,
                            status=FindingStatus.PROBABLE,
                            owasp_id=self.owasp_id,
                            plugin=self.name,
                            endpoint=url,
                            remediation=(
                                f"Decommission `{version_prefix}` if not actively needed. "
                                f"If required, implement identical security controls to the current version. "
                                f"Maintain an API inventory and decommission on schedule."
                            ),
                            references=[
                                "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"
                            ],
                            evidence=[Evidence(
                                request_method="GET",
                                request_url=url,
                                response_status=r_noauth.status_code,
                                response_body_snippet=r_noauth.text[:300],
                                note=f"Old version endpoint reachable — HTTP {r_noauth.status_code}",
                            )],
                        ))
                        break

                except Exception:
                    continue

    # ── Check 2: Non-production environment exposure ──────────────────────────

    async def _check_non_prod_exposure(
        self,
        http: httpx.AsyncClient,
        base: str,
        findings: list[Finding],
    ) -> None:
        """Check for /staging/, /dev/, /sandbox/ paths accessible on prod."""
        root = self._strip_to_base(base)
        for path in NON_PROD_PATHS:
            url = root + path
            try:
                r = await http.get(url)
                if r.status_code in (200, 201, 301, 302) and r.status_code != 404:
                    body_lower = r.text.lower()
                    # Filter out generic 200s that are just the root page
                    if len(r.text) < 50:
                        continue
                    env_keywords = any(
                        kw in body_lower
                        for kw in ["staging", "development", "sandbox", "test env", "non-prod", "debug"]
                    )
                    findings.append(Finding(
                        title=f"Non-Production Environment Exposed — {path}",
                        description=(
                            f"The `{path}` path is accessible on the production domain "
                            f"(HTTP {r.status_code}). Non-production environments typically "
                            f"disable authentication, logging, and rate limiting.\n\n"
                            f"**Impact**: Full access to an environment with relaxed security "
                            f"controls. Staging/dev environments often contain real data copies "
                            f"and debug credentials."
                        ),
                        severity=Severity.HIGH,
                        status=FindingStatus.CONFIRMED,
                        owasp_id=self.owasp_id,
                        plugin=self.name,
                        endpoint=url,
                        remediation=(
                            "Never deploy non-production environments on public-facing infrastructure. "
                            "Use separate subdomains behind IP allowlists. "
                            "Block all /staging, /dev, /test paths in production nginx/ALB config."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"
                        ],
                        evidence=[Evidence(
                            request_method="GET",
                            request_url=url,
                            response_status=r.status_code,
                            response_body_snippet=r.text[:400],
                            note=f"Non-production path accessible on production domain",
                        )],
                    ))
            except Exception:
                continue

    # ── Check 3: Internal / undocumented paths ────────────────────────────────

    async def _check_internal_paths(
        self,
        http: httpx.AsyncClient,
        base: str,
        findings: list[Finding],
    ) -> None:
        """Check for /internal/, /private/, /backend/ accessible paths."""
        root = self._strip_to_base(base)
        for path in INTERNAL_PATHS:
            url = root + path
            try:
                r = await http.get(url)
                if r.status_code in (200, 201) and len(r.text) > 30:
                    body = r.text
                    # Skip if it's just a redirect to homepage
                    if any(kw in body.lower() for kw in ["<html", "<!doctype", "login", "signin"]) and len(body) > 5000:
                        continue
                    findings.append(Finding(
                        title=f"Internal / Undocumented Endpoint Exposed — {path}",
                        description=(
                            f"The internal path `{path}` is publicly accessible (HTTP {r.status_code}). "
                            f"Internal endpoints are rarely hardened and often lack authentication, "
                            f"rate limiting, and output filtering.\n\n"
                            f"**Impact**: Direct access to internal service APIs, admin functionality, "
                            f"or service mesh endpoints that were never intended to be public."
                        ),
                        severity=Severity.HIGH,
                        status=FindingStatus.CONFIRMED,
                        owasp_id=self.owasp_id,
                        plugin=self.name,
                        endpoint=url,
                        remediation=(
                            "Block all /internal, /private, /backend paths at the reverse proxy level. "
                            "Internal endpoints should only be accessible within the private network. "
                            "Use network segmentation (VPC, private subnets) rather than relying on "
                            "path-based access control."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"
                        ],
                        evidence=[Evidence(
                            request_method="GET",
                            request_url=url,
                            response_status=r.status_code,
                            response_body_snippet=body[:400],
                            note="Internal/undocumented endpoint accessible without auth",
                        )],
                    ))
            except Exception:
                continue

    # ── Check 4: API documentation exposure in production ────────────────────

    async def _check_doc_exposure(
        self,
        http: httpx.AsyncClient,
        base: str,
        findings: list[Finding],
    ) -> None:
        """Check for accessible Swagger/OpenAPI docs in production."""
        root = self._strip_to_base(base)
        for path in DOC_PATHS:
            url = root + path
            try:
                r = await http.get(url)
                if r.status_code != 200:
                    continue
                body_lower = r.text.lower()
                is_doc = any(ind in body_lower for ind in DOC_INDICATORS)
                if not is_doc and "swagger" not in url and "openapi" not in url:
                    continue

                findings.append(Finding(
                    title=f"API Documentation Exposed in Production — {path}",
                    description=(
                        f"API documentation is publicly accessible at `{path}` (HTTP {r.status_code}). "
                        f"This provides attackers with a complete map of all endpoints, parameters, "
                        f"data models, and authentication schemes.\n\n"
                        f"**Impact**: Dramatically reduces attacker reconnaissance time. "
                        f"Exposes undocumented or internal endpoints that are listed in the spec "
                        f"but not intended to be public. Makes targeted attacks significantly easier."
                    ),
                    severity=Severity.MEDIUM,
                    status=FindingStatus.CONFIRMED,
                    owasp_id=self.owasp_id,
                    plugin=self.name,
                    endpoint=url,
                    remediation=(
                        "Disable API documentation endpoints in production, or protect them behind "
                        "authentication. If docs must be public, ensure they only document the "
                        "public-facing API surface. "
                        "Block /swagger, /swagger-ui, /api-docs, /redoc, /openapi.json at the "
                        "reverse proxy level in production environments."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"
                    ],
                    evidence=[Evidence(
                        request_method="GET",
                        request_url=url,
                        response_status=r.status_code,
                        response_body_snippet=r.text[:500],
                        note="API documentation accessible without authentication",
                    )],
                ))
                return  # one doc exposure finding is sufficient
            except Exception:
                continue
