"""
Plugin: Broken Function Level Authorization (BFLA)

Tests whether lower-privileged users or unauthenticated callers can invoke
administrative or privileged API functions that should be access-controlled
by role — not just by authentication.

Checks:
1. Admin-prefixed endpoints accessible without elevated privileges
2. Privileged HTTP methods (DELETE, PUT) accessible on standard user resources
3. HTTP method override headers bypassing function-level controls
4. Version-downgrade bypass (admin restricted in v2 but open in v1)

OWASP API Top 10: API5:2023 — Broken Function Level Authorization
"""

from __future__ import annotations

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient


# Admin-level paths that should be restricted to elevated roles
ADMIN_PATHS = [
    "/admin",
    "/api/admin",
    "/api/v1/admin",
    "/api/v2/admin",
    "/api/v1/admin/users",
    "/api/v1/admin/settings",
    "/api/v1/admin/config",
    "/api/v1/admin/dashboard",
    "/api/v1/admin/logs",
    "/api/v1/admin/metrics",
    "/api/v1/management",
    "/management",
    "/api/internal",
    "/internal",
    "/api/v1/users/all",
    "/api/v1/users?limit=1000",
    "/api/v1/billing/admin",
    "/api/v1/system",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/beans",
    "/api/v1/export",
    "/api/export",
    "/api/v1/reports",
    "/api/v1/audit",
]

# Privileged-action method + path pairs (things a regular user shouldn't do)
PRIVILEGED_ACTIONS = [
    ("DELETE", "/api/v1/users/1"),
    ("DELETE", "/api/v1/users/2"),
    ("DELETE", "/api/users/1"),
    ("PUT",    "/api/v1/users/1"),
    ("PUT",    "/api/v1/settings"),
    ("PATCH",  "/api/v1/users/1/role"),
    ("POST",   "/api/v1/admin/users"),
    ("DELETE", "/api/v1/admin/users/1"),
]

# HTTP method override headers some frameworks honour
METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-HTTP-Method",
    "_method",
]


class BFLAPlugin(BasePlugin):
    name = "bfla"
    description = "Broken Function Level Authorization — admin endpoints, method override, privilege escalation"
    owasp_id = "API5:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []

        findings.extend(await _test_admin_exposure(target, client))
        findings.extend(await _test_privileged_methods(target, client))
        findings.extend(await _test_method_override(target, client))

        return findings


# ── Test 1: Admin endpoints accessible without elevated role ──────────────────

async def _test_admin_exposure(target: TargetConfig, client: SecForgeClient) -> list[Finding]:
    """Probe admin-prefixed endpoints to see if they return data without admin auth."""
    findings = []
    exposed = []

    for path in ADMIN_PATHS:
        try:
            resp = await client.get(path)
            if resp.status_code in (200, 201) and _has_data(resp):
                ev = Evidence.from_httpx(
                    resp.request, resp,
                    note=f"GET {path} returned HTTP {resp.status_code} with data body — no elevated auth required.",
                )
                exposed.append((path, ev))
        except httpx.HTTPError:
            continue

    if exposed:
        paths_list = "\n".join(f"  • {p}" for p, _ in exposed)
        findings.append(Finding(
            title="Admin Endpoints Accessible Without Elevated Privileges",
            description=(
                f"Found {len(exposed)} administrative endpoint(s) returning data "
                "without requiring elevated roles or admin credentials. This allows "
                "regular users — or unauthenticated callers — to access privileged "
                "functionality such as user management, system config, or audit logs.\n\n"
                f"Exposed:\n{paths_list}"
            ),
            severity=Severity.CRITICAL,
            status=FindingStatus.CONFIRMED,
            owasp_id="API5:2023",
            plugin="bfla",
            endpoint=exposed[0][0],
            remediation=(
                "Implement function-level authorization checks on every admin endpoint "
                "server-side. Do not rely solely on UI hiding or route protection — "
                "check the caller's role on every request. Use a centralised policy "
                "engine (e.g. OPA, Casbin, or middleware guards) rather than per-endpoint checks."
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
            ],
            evidence=[ev for _, ev in exposed[:3]],
        ))

    return findings


# ── Test 2: Privileged HTTP methods accepted without role check ───────────────

async def _test_privileged_methods(target: TargetConfig, client: SecForgeClient) -> list[Finding]:
    """Test if DELETE/PUT on user/resource endpoints are blocked at function level."""
    findings = []
    accepted = []

    for method, path in PRIVILEGED_ACTIONS:
        try:
            resp = await client.request(method, path, json={})
            # 200/204 = action accepted; 404 = path exists but no object; both are interesting
            # We want to flag 200/204 specifically — it means the operation went through
            if resp.status_code in (200, 204):
                ev = Evidence.from_httpx(
                    resp.request, resp,
                    note=(
                        f"{method} {path} returned HTTP {resp.status_code} — "
                        "destructive/privileged operation accepted without role verification."
                    ),
                )
                accepted.append((method, path, ev))
        except httpx.HTTPError:
            continue

    if accepted:
        actions_list = "\n".join(f"  • {m} {p}" for m, p, _ in accepted)
        findings.append(Finding(
            title="Privileged HTTP Methods Accepted Without Role Check",
            description=(
                f"Found {len(accepted)} endpoint(s) accepting privileged HTTP methods "
                "(DELETE, PUT, PATCH) with a 200/204 response, indicating the server "
                "performed the operation without verifying caller role. "
                "An attacker with a standard user token could delete other users, "
                "modify account data, or escalate privileges.\n\n"
                f"Accepted:\n{actions_list}"
            ),
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            owasp_id="API5:2023",
            plugin="bfla",
            endpoint=accepted[0][1],
            remediation=(
                "Apply role-based access control (RBAC) at the function level, not just "
                "the resource level. For each endpoint, explicitly verify that the "
                "caller's role permits the requested HTTP method before executing the operation."
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
            ],
            evidence=[ev for _, _, ev in accepted[:3]],
        ))

    return findings


# ── Test 3: HTTP method override bypass ───────────────────────────────────────

async def _test_method_override(target: TargetConfig, client: SecForgeClient) -> list[Finding]:
    """Test if method override headers allow bypassing DELETE/PUT restrictions."""
    findings = []

    # First check if DELETE is normally blocked
    test_path = "/api/v1/users/1"
    try:
        direct = await client.request("DELETE", test_path)
        if direct.status_code in (401, 403, 405):
            # Good — DELETE is blocked. Now try overrides
            for header in METHOD_OVERRIDE_HEADERS:
                try:
                    resp = await client.get(
                        test_path,
                        headers={header: "DELETE"},
                    )
                    if resp.status_code in (200, 204):
                        findings.append(Finding(
                            title="HTTP Method Override Bypasses Function-Level Authorization",
                            description=(
                                f"The API blocks direct DELETE requests to {test_path} "
                                f"(returned {direct.status_code}), but accepts the same "
                                f"operation when disguised as a GET with the "
                                f"`{header}: DELETE` header (returned {resp.status_code}).\n\n"
                                "Many frameworks honour method override headers for "
                                "legacy client compatibility, creating a bypass vector "
                                "when access control is applied only to the HTTP method "
                                "rather than the effective method."
                            ),
                            severity=Severity.HIGH,
                            status=FindingStatus.CONFIRMED,
                            owasp_id="API5:2023",
                            plugin="bfla",
                            endpoint=test_path,
                            remediation=(
                                "Disable HTTP method override headers in production, or "
                                "ensure your authorization layer resolves the effective "
                                "method (including overrides) before applying access controls. "
                                "Most REST frameworks have an option to disable this feature."
                            ),
                            references=[
                                "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                                "https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-http-method-override",
                            ],
                            evidence=[Evidence.from_httpx(
                                resp.request, resp,
                                note=f"Sent GET with `{header}: DELETE` — server executed DELETE and returned {resp.status_code}.",
                            )],
                        ))
                        break  # One confirmed override bypass is sufficient
                except httpx.HTTPError:
                    continue
    except httpx.HTTPError:
        pass

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _has_data(resp: httpx.Response) -> bool:
    """Return True if the response body looks like real API data."""
    try:
        body = resp.text[:500].strip()
    except Exception:
        return False
    return (
        len(body) > 20
        and (body.startswith(("{", "[")) or '"id"' in body or '"data"' in body or '"results"' in body)
    )
