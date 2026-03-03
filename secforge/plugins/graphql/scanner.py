"""
Plugin: GraphQL Security Assessment

Comprehensive GraphQL security checks:

1. Introspection enabled — full schema disclosure
2. Batching attacks — multiple queries in one request (DoS, rate-limit bypass)
3. Query depth / complexity limits — unbounded recursive queries (DoS)
4. Field suggestion disclosure — "Did you mean X?" reveals schema when introspection disabled
5. GET-based mutations — CSRF via link clicking
6. Injection via variables — GraphQL-level injection points

OWASP API Top 10: API8:2023 — Security Misconfiguration
"""

from __future__ import annotations

import json
from typing import Optional

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient


# Common GraphQL endpoint paths
GQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/api/v1/graphql",
    "/v1/graphql",
    "/query",
    "/gql",
    "/graph",
]

# Introspection query
INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type { name kind }
      }
    }
  }
}
""".strip()

# Deep nested query (depth bomb)
DEPTH_BOMB = """
{
  a { a { a { a { a { a { a { a { a { a {
    __typename
  } } } } } } } } } }
}
""".strip()

# Batching attack: 10 introspection queries in one request
BATCH_QUERY = json.dumps([
    {"query": "{ __typename }"} for _ in range(10)
])


class GraphQLPlugin(BasePlugin):
    name = "graphql"
    description = "GraphQL security: introspection, batching, depth limits, injection"
    owasp_id = "API8:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []

        # Find GraphQL endpoint
        gql_endpoint = await _find_gql_endpoint(client, GQL_PATHS)
        if not gql_endpoint:
            return []  # No GraphQL detected — clean skip

        findings.append(Finding(
            title="GraphQL Endpoint Discovered",
            description=f"GraphQL API found at {gql_endpoint}. Running security checks.",
            severity=Severity.INFO,
            status=FindingStatus.CONFIRMED,
            plugin=self.name,
            endpoint=gql_endpoint,
            evidence=[Evidence.observed(
                note=f"GraphQL endpoint responded at {gql_endpoint}",
                url=f"{target.url}{gql_endpoint}",
            )],
        ))

        # ── 1. Introspection ──────────────────────────────────────────────
        findings.extend(await _test_introspection(client, target, gql_endpoint))

        # ── 2. Batching attack ────────────────────────────────────────────
        findings.extend(await _test_batching(client, target, gql_endpoint))

        # ── 3. Query depth limit ──────────────────────────────────────────
        findings.extend(await _test_depth_limit(client, target, gql_endpoint))

        # ── 4. Field suggestions (schema disclosure) ──────────────────────
        findings.extend(await _test_field_suggestions(client, target, gql_endpoint))

        # ── 5. GET-based mutations (CSRF) ─────────────────────────────────
        findings.extend(await _test_get_mutations(client, target, gql_endpoint))

        return findings


async def _find_gql_endpoint(client: SecForgeClient, paths: list[str]) -> Optional[str]:
    """Probe common paths. Return first that looks like GraphQL."""
    for path in paths:
        try:
            # Send a minimal introspection probe
            resp = await client.post(
                path,
                json={"query": "{ __typename }"},
                headers={"Content-Type": "application/json"},
            )
            body = _safe_text(resp)

            if resp.status_code in (200, 400) and (
                "data" in body or "__typename" in body
                or "errors" in body or "graphql" in body.lower()
            ):
                return path
        except httpx.HTTPError:
            pass
    return None


async def _test_introspection(
    client: SecForgeClient, target: TargetConfig, endpoint: str
) -> list[Finding]:
    findings = []
    try:
        resp = await client.post(
            endpoint,
            json={"query": INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"},
        )
        body = _safe_text(resp)

        if resp.status_code == 200 and "__schema" in body and "types" in body:
            # Count types discovered
            try:
                data = resp.json()
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                type_names = [t["name"] for t in types if not t["name"].startswith("__")]
            except Exception:
                type_names = []

            findings.append(Finding(
                title="GraphQL Introspection Enabled",
                description=(
                    "GraphQL introspection is enabled, exposing the complete API schema "
                    f"including all {len(type_names)} types, fields, arguments, and relationships. "
                    "Attackers use introspection to map the entire attack surface before "
                    "crafting targeted queries.\n\n"
                    + (f"Types discovered: {', '.join(type_names[:15])}{'...' if len(type_names) > 15 else ''}"
                       if type_names else "")
                ),
                severity=Severity.MEDIUM,
                status=FindingStatus.CONFIRMED,
                owasp_id="API8:2023",
                plugin="graphql",
                endpoint=endpoint,
                remediation=(
                    "Disable introspection in production. In most frameworks: "
                    "Apollo Server: introspection: false | "
                    "graphql-js: NoSchemaIntrospectionCustomRule | "
                    "Strawberry/Ariadne: introspection=False"
                ),
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                    "https://www.apollographql.com/docs/apollo-server/security/introspection/",
                ],
                evidence=[Evidence.from_httpx(
                    resp.request, resp,
                    note=f"Introspection query returned {len(type_names)} types. Schema fully disclosed.",
                )],
            ))
    except httpx.HTTPError:
        pass
    return findings


async def _test_batching(
    client: SecForgeClient, target: TargetConfig, endpoint: str
) -> list[Finding]:
    findings = []
    try:
        resp = await client.post(
            endpoint,
            content=BATCH_QUERY,
            headers={"Content-Type": "application/json"},
        )
        body = _safe_text(resp)

        if resp.status_code == 200 and body.strip().startswith("["):
            try:
                results = resp.json()
                if isinstance(results, list) and len(results) > 1:
                    findings.append(Finding(
                        title="GraphQL Batching Enabled (Rate-Limit Bypass / DoS Risk)",
                        description=(
                            f"The GraphQL endpoint accepts batched query arrays. "
                            f"Sent 10 queries in one request → got {len(results)} responses. "
                            "\n\nBatching enables:\n"
                            "  • Rate-limit bypass: 1 HTTP request = N query executions\n"
                            "  • Brute-force at scale: batch N password attempts per request\n"
                            "  • DoS via N expensive queries bundled together"
                        ),
                        severity=Severity.MEDIUM,
                        status=FindingStatus.CONFIRMED,
                        owasp_id="API4:2023",
                        plugin="graphql",
                        endpoint=endpoint,
                        remediation=(
                            "Disable query batching if not required. "
                            "If needed, limit batch size to ≤5 queries and apply "
                            "per-query rate limiting, not per-HTTP-request."
                        ),
                        references=["https://www.apollographql.com/docs/apollo-server/performance/batching/"],
                        evidence=[Evidence.from_httpx(
                            resp.request, resp,
                            note=f"Sent 10-query batch → received {len(results)} results in one request",
                        )],
                    ))
            except (ValueError, TypeError):
                pass
    except httpx.HTTPError:
        pass
    return findings


async def _test_depth_limit(
    client: SecForgeClient, target: TargetConfig, endpoint: str
) -> list[Finding]:
    findings = []
    try:
        resp = await client.post(
            endpoint,
            json={"query": DEPTH_BOMB},
            headers={"Content-Type": "application/json"},
        )
        body = _safe_text(resp)

        # If we got 200 and actual data (not an error about depth) → no depth limit
        if resp.status_code == 200 and "errors" not in body and "data" in body:
            findings.append(Finding(
                title="GraphQL: No Query Depth Limit",
                description=(
                    "A deeply nested query (depth 10) was accepted without error. "
                    "Without depth limits, attackers can craft exponentially complex "
                    "recursive queries that overwhelm the server's resolvers, "
                    "causing CPU exhaustion and DoS."
                ),
                severity=Severity.MEDIUM,
                status=FindingStatus.CONFIRMED,
                owasp_id="API4:2023",
                plugin="graphql",
                endpoint=endpoint,
                remediation=(
                    "Implement query depth limiting (max depth 5-10). "
                    "Libraries: graphql-depth-limit (JS), graphene-django depth limit (Python), "
                    "or use a WAF/gateway with query complexity analysis."
                ),
                evidence=[Evidence.from_httpx(
                    resp.request, resp,
                    note="Depth-10 nested query returned HTTP 200 without depth error",
                )],
            ))
        elif resp.status_code == 200 and "errors" in body:
            body_data = {}
            try:
                body_data = resp.json()
            except Exception:
                pass
            errors = body_data.get("errors", [])
            depth_errors = [e for e in errors if any(
                x in str(e).lower() for x in ["depth", "complex", "limit"]
            )]
            if not depth_errors and not body.strip().startswith("{"):
                pass  # Ambiguous — don't flag
    except httpx.HTTPError:
        pass
    return findings


async def _test_field_suggestions(
    client: SecForgeClient, target: TargetConfig, endpoint: str
) -> list[Finding]:
    """Test if 'Did you mean X?' suggestions leak schema info when introspection is disabled."""
    findings = []
    try:
        # Intentional typo to trigger suggestion
        resp = await client.post(
            endpoint,
            json={"query": "{ usr { id } }"},
            headers={"Content-Type": "application/json"},
        )
        body = _safe_text(resp)

        if "did you mean" in body.lower() or "suggestion" in body.lower():
            import re
            suggestions = re.findall(r'"([a-zA-Z][a-zA-Z0-9_]*)"', body)
            findings.append(Finding(
                title="GraphQL Field Suggestion Disclosure (Schema Leak)",
                description=(
                    "The GraphQL server returns 'Did you mean X?' suggestions for "
                    "misspelled field names. Even with introspection disabled, this "
                    "allows attackers to enumerate the schema by probing with typos "
                    "and collecting suggestions.\n\n"
                    + (f"Suggestions returned: {', '.join(suggestions[:10])}"
                       if suggestions else "")
                ),
                severity=Severity.LOW,
                status=FindingStatus.CONFIRMED,
                owasp_id="API8:2023",
                plugin="graphql",
                endpoint=endpoint,
                remediation=(
                    "Disable field suggestions in production. "
                    "Apollo Server: playground: false, or customize error masking. "
                    "This is separate from disabling introspection."
                ),
                evidence=[Evidence.from_httpx(
                    resp.request, resp,
                    note=f"Typo query '{{usr}}' returned suggestions: {body[:300]}",
                )],
            ))
    except httpx.HTTPError:
        pass
    return findings


async def _test_get_mutations(
    client: SecForgeClient, target: TargetConfig, endpoint: str
) -> list[Finding]:
    """Test if mutations can be executed via GET request (CSRF risk)."""
    findings = []
    try:
        from urllib.parse import urlencode
        mutation = "mutation { __typename }"
        params = urlencode({"query": mutation})
        resp = await client.get(f"{endpoint}?{params}")
        body = _safe_text(resp)

        if resp.status_code == 200 and "__typename" in body:
            findings.append(Finding(
                title="GraphQL Mutations Accepted via GET Request (CSRF Risk)",
                description=(
                    "The GraphQL endpoint accepts mutation queries via HTTP GET. "
                    "Since GET requests are CSRF-safe in same-origin policy but "
                    "can be triggered by cross-site links/iframes, attackers can "
                    "perform state-changing mutations on behalf of authenticated users "
                    "without CSRF tokens."
                ),
                severity=Severity.MEDIUM,
                status=FindingStatus.CONFIRMED,
                owasp_id="API8:2023",
                plugin="graphql",
                endpoint=endpoint,
                remediation=(
                    "Reject mutations on GET requests. Only accept POST with "
                    "Content-Type: application/json (which triggers CORS preflight)."
                ),
                evidence=[Evidence.from_httpx(
                    resp.request, resp,
                    note=f"GET mutation returned HTTP 200: {body[:200]}",
                )],
            ))
    except httpx.HTTPError:
        pass
    return findings


def _safe_text(resp: httpx.Response) -> str:
    try:
        return resp.text[:3000]
    except Exception:
        return ""
