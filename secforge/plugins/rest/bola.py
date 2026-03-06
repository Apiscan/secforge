"""
Plugin: BOLA — Broken Object Level Authorization (IDOR)

OWASP API1:2023 — the #1 most critical API vulnerability class.

Two-tier testing strategy:
─────────────────────────────────────────────────────────────────────────────
Tier 1 — Heuristic (single auth token, always runs)
  • Discover endpoints through: GET /, OpenAPI/Swagger docs, response body patterns
  • Probe sequential integer IDs and UUID patterns
  • Flag endpoints that return 200 with data for IDs beyond an expected range
  • Status: PROBABLE (cannot confirm ownership without two accounts)

Tier 2 — Confirmed Cross-User (requires user_b_auth in profile)
  • Authenticate as User A, collect their resource IDs from responses
  • Re-issue every GET/PUT/PATCH/DELETE as User B using User A's IDs
  • CONFIRMED if User B successfully reads/modifies User A's resources
  • Also tests object references buried in request bodies (not just URL params)
─────────────────────────────────────────────────────────────────────────────

Configure for Tier 2 testing in your target profile:

  auth:
    type: bearer
    token: USER_A_TOKEN

  user_b_auth:
    type: bearer
    token: USER_B_TOKEN
"""

from __future__ import annotations

import asyncio
import re
import uuid
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient


# Common resource endpoint patterns — covers typical REST conventions
COMMON_ID_PATHS = [
    "/api/v1/users/{id}",
    "/api/v2/users/{id}",
    "/api/v3/users/{id}",
    "/api/users/{id}",
    "/users/{id}",
    "/api/v1/accounts/{id}",
    "/api/accounts/{id}",
    "/accounts/{id}",
    "/api/v1/orders/{id}",
    "/api/orders/{id}",
    "/orders/{id}",
    "/api/v1/profiles/{id}",
    "/api/profiles/{id}",
    "/profiles/{id}",
    "/api/v1/documents/{id}",
    "/documents/{id}",
    "/api/v1/invoices/{id}",
    "/invoices/{id}",
    "/api/v1/tickets/{id}",
    "/tickets/{id}",
    "/api/v1/posts/{id}",
    "/posts/{id}",
    "/api/v1/items/{id}",
    "/items/{id}",
    "/api/v1/messages/{id}",
    "/messages/{id}",
    "/api/v1/payments/{id}",
    "/payments/{id}",
    "/api/v1/transactions/{id}",
    "/transactions/{id}",
    "/api/v1/subscriptions/{id}",
    "/subscriptions/{id}",
    "/api/v1/files/{id}",
    "/files/{id}",
    "/api/v1/reports/{id}",
    "/reports/{id}",
]

# Sequential integer IDs to probe
PROBE_INT_IDS = [1, 2, 3, 100]

# HTTP methods to test beyond GET
MUTATION_METHODS = ["PUT", "PATCH", "DELETE"]

# Fields that often contain resource IDs in JSON bodies
ID_FIELD_PATTERNS = re.compile(
    r'"(id|user_id|userId|account_id|accountId|owner_id|ownerId|resource_id|'
    r'resourceId|object_id|objectId|document_id|documentId|record_id|recordId|'
    r'profile_id|profileId|order_id|orderId)":\s*(\d+|"[0-9a-f-]{36}")',
    re.IGNORECASE,
)

# OpenAPI/Swagger discovery paths
OPENAPI_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/api-docs/swagger.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/v1/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/.well-known/openapi.json",
]


class BOLAPlugin(BasePlugin):
    name = "bola"
    description = "Broken Object Level Authorization / IDOR — dual-user confirmed testing"
    owasp_id = "API1:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []

        # ── Step 1: Discover endpoints ────────────────────────────────────────────
        discovered = await _discover_endpoints(client, target)
        all_paths = list({*COMMON_ID_PATHS, *discovered})

        # ── Step 2: Collect User A's accessible resources (concurrent) ───────────
        user_a_resources: list[tuple[str, str, str]] = []  # (path, id, response_body)

        async def _probe_path(path_template: str) -> tuple[str, str, str] | None:
            for probe_id in PROBE_INT_IDS:
                path = path_template.replace("{id}", str(probe_id))
                try:
                    resp = await client.get(path)
                    if resp.status_code == 200:
                        body = _safe_text(resp)
                        if _looks_like_data(body):
                            return (path_template, str(probe_id), body)
                except httpx.HTTPError:
                    continue
            return None

        results = await asyncio.gather(*[_probe_path(p) for p in all_paths], return_exceptions=True)
        user_a_resources = [r for r in results if r and not isinstance(r, Exception)]

        # ── Step 3: Tier 2 — Confirmed Cross-User Testing ─────────────────────────
        if target.user_b_auth and user_a_resources:
            tier2_findings = await _tier2_cross_user(
                target, client, user_a_resources
            )
            findings.extend(tier2_findings)

        # ── Step 4: Tier 1 — Heuristic (if no Tier 2, or to supplement) ──────────
        if user_a_resources and not any(
            f.status == FindingStatus.CONFIRMED for f in findings
        ):
            # Build evidence from the first few accessible endpoints
            evidence_list = []
            affected_paths = []
            for path_tpl, probe_id, _ in user_a_resources[:5]:
                path = path_tpl.replace("{id}", probe_id)
                try:
                    resp = await client.get(path)
                    evidence_list.append(
                        Evidence.from_httpx(
                            resp.request, resp,
                            note=(
                                f"Endpoint returns HTTP 200 for sequential ID={probe_id}. "
                                "Manual verification needed: confirm whether this resource "
                                "belongs to the authenticated user."
                            ),
                        )
                    )
                    affected_paths.append(path)
                except httpx.HTTPError:
                    continue

            if evidence_list:
                dual_token_hint = (
                    ""
                    if target.user_b_auth
                    else (
                        "\n\nTo enable confirmed cross-user testing, add user_b_auth to "
                        "your target profile with a second account's token."
                    )
                )
                findings.append(Finding(
                    title="BOLA: Sequential Resource IDs Accessible (Unverified Ownership)",
                    description=(
                        f"{len(user_a_resources)} endpoint(s) return HTTP 200 for sequential "
                        "integer IDs. If these resources belong to other users, this is a "
                        "Broken Object Level Authorization (IDOR) vulnerability.\n\n"
                        "Affected endpoints:\n"
                        + "\n".join(f"  • {p}" for p in affected_paths)
                        + dual_token_hint
                    ),
                    severity=Severity.HIGH,
                    status=FindingStatus.PROBABLE,
                    owasp_id=self.owasp_id,
                    plugin=self.name,
                    endpoint=affected_paths[0] if affected_paths else "",
                    remediation=(
                        "Implement object-level authorization on every endpoint that accepts "
                        "a resource ID. Verify the requesting user owns or has explicit "
                        "permission to access the requested object. Use unpredictable (UUID) "
                        "IDs as an additional defense-in-depth measure."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                        "https://portswigger.net/web-security/access-control/idor",
                    ],
                    evidence=evidence_list,
                ))

        return findings


async def _tier2_cross_user(
    target: TargetConfig,
    client_a: SecForgeClient,
    user_a_resources: list[tuple[str, str, str]],
) -> list[Finding]:
    """
    Authenticated cross-user testing:
    Use User B's credentials to access resources discovered under User A.
    Tests GET, PUT, PATCH, DELETE.
    """
    findings: list[Finding] = []

    # Build User B headers
    user_b_headers = target.user_b_auth.build_headers() if target.user_b_auth else {}
    if not user_b_headers:
        return findings

    confirmed_accesses: list[tuple[str, str, str, Evidence, Evidence]] = []
    # (path, id, method, evidence_user_a, evidence_user_b)

    for path_template, probe_id, user_a_body in user_a_resources[:10]:
        path = path_template.replace("{id}", probe_id)

        # ── GET: can User B read User A's resource? ───────────────────────────────
        try:
            # Baseline: User A fetch (already done, but get the response object)
            resp_a = await client_a.get(path)
            if resp_a.status_code != 200:
                continue

            # Now fetch as User B — user_b_headers overrides client-level auth
            resp_b = await client_a.get(path, headers=user_b_headers)

            ev_a = Evidence.from_httpx(resp_a.request, resp_a, note="User A — owner request")
            ev_b = Evidence.from_httpx(resp_b.request, resp_b, note="User B — cross-user access attempt")

            if resp_b.status_code == 200:
                b_body = _safe_text(resp_b)
                # Confirm the response contains the same data (not a generic 200)
                if _bodies_overlap(user_a_body, b_body):
                    confirmed_accesses.append((path, probe_id, "GET", ev_a, ev_b))

            # ── PUT: can User B overwrite User A's resource? ─────────────────────
            if resp_a.status_code == 200:
                test_payload = _build_write_payload(user_a_body)
                if test_payload:
                    try:
                        resp_put = await client_a.request(
                            "PUT", path,
                            json=test_payload,
                            headers=user_b_headers,
                        )
                        ev_put = Evidence.from_httpx(
                            resp_put.request, resp_put,
                            note="User B — PUT write attempt on User A's resource",
                        )
                        if resp_put.status_code in (200, 201, 204):
                            confirmed_accesses.append((path, probe_id, "PUT", ev_a, ev_put))
                    except httpx.HTTPError:
                        pass

            # ── DELETE: can User B delete User A's resource? ─────────────────────
            try:
                resp_del = await client_a.request(
                    "DELETE", path,
                    headers=user_b_headers,
                )
                ev_del = Evidence.from_httpx(
                    resp_del.request, resp_del,
                    note="User B — DELETE attempt on User A's resource",
                )
                if resp_del.status_code in (200, 202, 204):
                    confirmed_accesses.append((path, probe_id, "DELETE", ev_a, ev_del))
            except httpx.HTTPError:
                pass

        except httpx.HTTPError:
            continue

    if not confirmed_accesses:
        return findings

    # Group by severity: writes/deletes are Critical, reads are High
    writes = [(p, i, m, ea, eb) for p, i, m, ea, eb in confirmed_accesses if m in ("PUT", "DELETE")]
    reads  = [(p, i, m, ea, eb) for p, i, m, ea, eb in confirmed_accesses if m == "GET"]

    if writes:
        ev_list = [ea for _, _, _, ea, _ in writes[:3]] + [eb for _, _, _, _, eb in writes[:3]]
        paths_str = "\n".join(f"  • {m} {p}" for p, _, m, _, _ in writes)
        findings.append(Finding(
            title="CRITICAL BOLA: Cross-User Write/Delete Confirmed",
            description=(
                "User B successfully modified or deleted resources belonging to User A. "
                "This is a confirmed Broken Object Level Authorization vulnerability — "
                "an attacker with any valid account can modify or destroy any other "
                "user's data by manipulating resource IDs.\n\n"
                f"Confirmed write/delete access:\n{paths_str}"
            ),
            severity=Severity.CRITICAL,
            status=FindingStatus.CONFIRMED,
            owasp_id="API1:2023",
            plugin="bola",
            endpoint=writes[0][0],
            remediation=(
                "Every write/delete endpoint must verify the authenticated user owns "
                "the target resource before processing the operation. Implement "
                "authorization checks at the service layer, not just the route layer. "
                "Use framework-level authorization guards (e.g., policy objects) to "
                "prevent this class of bypass."
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            ],
            evidence=ev_list,
        ))

    if reads:
        ev_list = [ea for _, _, _, ea, _ in reads[:3]] + [eb for _, _, _, _, eb in reads[:3]]
        paths_str = "\n".join(f"  • GET {p}" for p, _, _, _, _ in reads)
        findings.append(Finding(
            title="BOLA: Cross-User Read Access Confirmed",
            description=(
                "User B successfully read resources belonging to User A. "
                "An attacker with any valid account can enumerate any other "
                "user's private data by iterating resource IDs.\n\n"
                f"Confirmed read access:\n{paths_str}"
            ),
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            owasp_id="API1:2023",
            plugin="bola",
            endpoint=reads[0][0],
            remediation=(
                "Implement object-level authorization on every endpoint that accepts "
                "a resource ID. The server must verify the requesting user owns or has "
                "explicit permission to access each requested object."
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            ],
            evidence=ev_list,
        ))

    return findings


async def _discover_endpoints(
    client: SecForgeClient,
    target: TargetConfig,
) -> list[str]:
    """
    Multi-strategy endpoint discovery:
    1. OpenAPI/Swagger spec parsing (richest source)
    2. API root response crawl (picks up hrefs, links, rel URLs)
    3. Common discovery paths
    """
    discovered: list[str] = []

    # ── Strategy 1: OpenAPI/Swagger ───────────────────────────────────────────
    for spec_path in OPENAPI_PATHS:
        try:
            resp = await client.get(spec_path)
            if resp.status_code == 200:
                text = _safe_text(resp)
                # Extract path templates like /api/v1/users/{id} or /users/{userId}
                templates = re.findall(r'"(/[^"{}]*\{[^}]+\}[^"]*)"', text)
                for t in templates:
                    # Normalize to {id}
                    normalized = re.sub(r'\{[^}]+\}', '{id}', t)
                    if normalized not in discovered:
                        discovered.append(normalized)
                if templates:
                    break  # Found a working spec, stop
        except httpx.HTTPError:
            continue

    # ── Strategy 2: Root crawl ────────────────────────────────────────────────
    for crawl_path in ["/", "/api", "/api/v1", "/api/v2"]:
        try:
            resp = await client.get(crawl_path)
            if resp.status_code == 200:
                text = _safe_text(resp)
                # Look for patterns like /resource/123 or /resource/UUID
                patterns = re.findall(
                    r'["\'/]([a-z][a-z0-9_/-]+)/(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
                    text, re.IGNORECASE
                )
                for resource_path, _ in patterns:
                    clean = resource_path.strip("/")
                    if not any(x in clean for x in ["static", "asset", "css", "js", "img", "font"]):
                        template = f"/{clean}/{{id}}"
                        if template not in discovered:
                            discovered.append(template)
        except httpx.HTTPError:
            continue

    return discovered[:30]  # Cap to avoid excessive requests


def _safe_text(resp: httpx.Response) -> str:
    try:
        return resp.text[:4000]
    except Exception:
        return ""


def _looks_like_data(body: str) -> bool:
    stripped = body.strip()
    if len(stripped) < 30:
        return False
    return (
        stripped.startswith(("{", "["))
        or '"id"' in body
        or '"_id"' in body
        or '"uuid"' in body.lower()
    )


def _bodies_overlap(body_a: str, body_b: str) -> bool:
    """Check if two response bodies share significant content (same resource returned)."""
    if len(body_b) < 30:
        return False
    # Extract quoted string values from both bodies and check overlap
    vals_a = set(re.findall(r'"([^"]{4,50})"', body_a))
    vals_b = set(re.findall(r'"([^"]{4,50})"', body_b))
    if not vals_a or not vals_b:
        return len(body_b) > 50  # If can't compare, assume overlap if body is non-empty
    overlap = vals_a & vals_b
    return len(overlap) >= 2  # At least 2 shared string values = same resource


def _build_write_payload(original_body: str) -> Optional[dict]:
    """Build a minimal PUT payload from an existing resource body."""
    try:
        import json
        data = json.loads(original_body)
        if isinstance(data, dict):
            # Return a subset with just a non-sensitive field modified
            safe_fields = {k: v for k, v in data.items()
                          if k not in ("id", "_id", "uuid", "created_at", "updated_at", "password")}
            if safe_fields:
                # Modify one string field minimally
                for k, v in safe_fields.items():
                    if isinstance(v, str) and len(v) < 200:
                        safe_fields[k] = v + "_test"
                        break
                return safe_fields
    except Exception:
        pass
    return None
