"""
Phase 6 Plugin Tests — Injection, Mass Assignment, Misconfiguration, BOLA (rewrite)
Uses respx for HTTP mocking. Routes are matched in order; add specific routes first,
catch-all fallback last.
"""

import pytest
import respx
import httpx

from secforge.plugins.rest.injection import InjectionPlugin
from secforge.plugins.rest.mass_assignment import MassAssignmentPlugin
from secforge.plugins.rest.misconfiguration import MisconfigurationPlugin
from secforge.plugins.rest.bola import BOLAPlugin
from secforge.models.target import TargetConfig, AuthConfig, ScopeConfig
from secforge.models.enums import Severity, FindingStatus
from secforge.core.client import SecForgeClient


# ── Fixtures ───────────────────────────────────────────────────────────────────

from secforge.models.target import ScanOptions

@pytest.fixture
def target():
    return TargetConfig(
        url="https://api.example.com",
        name="test",
        auth=AuthConfig(type="bearer", token="userA_token"),
        scope=ScopeConfig(authorized=True),
        options=ScanOptions(rate_limit=500),  # no rate limiting in tests
    )


@pytest.fixture
def target_dual():
    return TargetConfig(
        url="https://api.example.com",
        name="test-dual",
        auth=AuthConfig(type="bearer", token="userA_token"),
        user_b_auth=AuthConfig(type="bearer", token="userB_token"),
        scope=ScopeConfig(authorized=True),
        options=ScanOptions(rate_limit=500),  # no rate limiting in tests
    )


async def run_plugin(plugin_cls, target, setup_mock_fn):
    with respx.mock(base_url="https://api.example.com", assert_all_called=False) as mock:
        setup_mock_fn(mock)
        # Catch-all fallback: any unmatched route returns 404
        mock.route().mock(return_value=httpx.Response(404))
        async with SecForgeClient(target) as client:
            return await plugin_cls().run(target, client)


# ── Misconfiguration Tests ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_misconfiguration_actuator_env_exposed(target):
    """/actuator/env exposed with secrets → CRITICAL finding."""
    env_payload = {
        "activeProfiles": [],
        "propertySources": [{
            "name": "systemEnvironment",
            "properties": {
                "DATABASE_URL": {"value": "postgres://user:pass@db:5432/prod"},
                "SECRET_KEY": {"value": "super_secret_key_123"},
            }
        }]
    }

    def setup(mock):
        mock.get("/actuator/env").mock(return_value=httpx.Response(200, json=env_payload))

    findings = await run_plugin(MisconfigurationPlugin, target, setup)
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1, f"Expected CRITICAL for /actuator/env, got: {[f.title for f in findings]}"


@pytest.mark.asyncio
async def test_misconfiguration_actuator_info_only(target):
    """Only /actuator/info exposed (low-risk) → no CRITICAL finding."""
    def setup(mock):
        mock.get("/actuator/info").mock(return_value=httpx.Response(
            200, json={"build": {"version": "1.0.0"}}
        ))

    findings = await run_plugin(MisconfigurationPlugin, target, setup)
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) == 0


@pytest.mark.asyncio
async def test_misconfiguration_env_file_exposed(target):
    """.env file accessible with credentials → CRITICAL finding."""
    env_content = "DATABASE_URL=postgres://admin:s3cr3t@db/prod\nSECRET_KEY=abc123\nAWS_SECRET_ACCESS_KEY=xyzxyz"

    def setup(mock):
        mock.get("/.env").mock(return_value=httpx.Response(200, text=env_content))

    findings = await run_plugin(MisconfigurationPlugin, target, setup)
    env_findings = [f for f in findings if ".env" in f.title or "sensitive" in f.title.lower()]
    assert len(env_findings) >= 1
    assert any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in env_findings)


@pytest.mark.asyncio
async def test_misconfiguration_stack_trace_in_error(target):
    """Stack trace in 500 response → MEDIUM verbose error finding."""
    trace_body = (
        '{"error":"Internal Server Error",'
        '"traceback":"Traceback (most recent call last):\\n  File \\"/app/api.py\\", '
        'line 87\\nValueError: invalid literal"}'
    )

    def setup(mock):
        mock.get("/api/v1/users/INVALID_ID_THAT_SHOULD_NOT_EXIST_SECFORGE").mock(
            return_value=httpx.Response(500, text=trace_body)
        )
        mock.get("/api/v1/NONEXISTENT_ENDPOINT_SECFORGE/test").mock(
            return_value=httpx.Response(500, text=trace_body)
        )
        mock.get("/api/NONEXISTENT_SECFORGE").mock(
            return_value=httpx.Response(500, text=trace_body)
        )

    findings = await run_plugin(MisconfigurationPlugin, target, setup)
    verbose = [f for f in findings if "verbose" in f.title.lower() or "stack" in f.title.lower()]
    assert len(verbose) >= 1


@pytest.mark.asyncio
async def test_misconfiguration_clean(target):
    """Everything 404 → no CRITICAL or HIGH findings."""
    def setup(mock):
        pass  # Catch-all returns 404

    findings = await run_plugin(MisconfigurationPlugin, target, setup)
    bad = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(bad) == 0


# ── Mass Assignment Tests ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_mass_assignment_field_leak_422(target):
    """422 error reveals privilege fields → MEDIUM finding."""
    leak_body = (
        '{"detail":[{"loc":["body","role"],"msg":"extra fields not permitted"},'
        '{"loc":["body","isAdmin"],"msg":"extra fields not permitted"},'
        '{"loc":["body","plan"],"msg":"extra fields not permitted"}]}'
    )

    def setup(mock):
        mock.get("/api/v1/users/me").mock(return_value=httpx.Response(200, json={"id": 1}))
        mock.put("/api/v1/users/me").mock(return_value=httpx.Response(422, text=leak_body))
        mock.patch("/api/v1/users/me").mock(return_value=httpx.Response(422, text=leak_body))
        mock.post("/api/v1/users").mock(return_value=httpx.Response(422, text=leak_body))

    findings = await run_plugin(MassAssignmentPlugin, target, setup)
    leaked = [f for f in findings if "exposed" in f.title.lower() or "leak" in f.title.lower()
              or "field" in f.title.lower()]
    assert len(leaked) >= 1


@pytest.mark.asyncio
async def test_mass_assignment_role_accepted(target):
    """PATCH /me with role=admin returns role:admin in response → CRITICAL/HIGH finding."""
    def setup(mock):
        mock.get("/api/v1/users/me").mock(return_value=httpx.Response(
            200, json={"id": 1, "email": "user@example.com", "role": "user"}
        ))
        mock.patch("/api/v1/users/me").mock(return_value=httpx.Response(
            200, json={"id": 1, "email": "user@example.com", "role": "admin"}
        ))
        mock.put("/api/v1/users/me").mock(return_value=httpx.Response(
            200, json={"id": 1, "email": "user@example.com", "role": "admin"}
        ))

    findings = await run_plugin(MassAssignmentPlugin, target, setup)
    escalation = [f for f in findings
                  if "mass assignment" in f.title.lower() or "role" in f.title.lower()
                  or "privilege" in f.title.lower()]
    assert len(escalation) >= 1


@pytest.mark.asyncio
async def test_mass_assignment_rejects_extra_fields(target):
    """API returns 400 for unknown fields → no HIGH/CRITICAL findings."""
    def setup(mock):
        mock.get("/api/v1/users/me").mock(return_value=httpx.Response(200, json={"id": 1}))
        mock.put("/api/v1/users/me").mock(return_value=httpx.Response(
            400, json={"error": "Unknown fields not allowed"}
        ))
        mock.patch("/api/v1/users/me").mock(return_value=httpx.Response(
            400, json={"error": "Unknown fields not allowed"}
        ))

    findings = await run_plugin(MassAssignmentPlugin, target, setup)
    bad = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(bad) == 0


# ── Injection Tests ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_injection_sql_error_confirmed(target):
    """SQL payload triggers DB error in response → CRITICAL CONFIRMED finding."""
    sql_error_body = (
        '{"error":"You have an error in your SQL syntax; '
        'check the manual for the right syntax near apostrophe at line 1"}'
    )
    # URL-encoded versions of common SQL injection chars
    SQL_SIGNALS = ("%27", "%22", "%60", "--", "OR+1", "UNION", "WAITFOR", "SLEEP")

    def handler(request):
        qs = str(request.url.query)
        # baseline value "1" returns clean response
        if qs in ("search=1", "q=1", "query=1", "keyword=1", "term=1", "id=1",
                   "filter=1", "category=1", "type=1"):
            return httpx.Response(200, json={"results": []})
        # Any injection payload (URL-encoded quote chars etc.) triggers SQL error
        if any(s in qs.upper() for s in SQL_SIGNALS) or len(qs) > 20:
            return httpx.Response(500, text=sql_error_body)
        return httpx.Response(200, json={"results": []})

    def setup(mock):
        mock.get("/api/v1/search").mock(side_effect=handler)

    findings = await run_plugin(InjectionPlugin, target, setup)
    sql = [f for f in findings if "sql" in f.title.lower()]
    assert len(sql) >= 1, f"Expected SQL injection finding, got: {[f.title for f in findings]}"
    assert any(f.severity == Severity.CRITICAL for f in sql)
    assert any(f.status == FindingStatus.CONFIRMED for f in sql)


@pytest.mark.asyncio
async def test_injection_nosql_error_confirmed(target):
    """NoSQL operator in query triggers MongoDB error → CRITICAL CONFIRMED finding."""
    mongo_error = '{"error":"MongoError: Cast to ObjectId failed for value"}'
    # URL-encoded $ sign is %24
    NOSQL_SIGNALS = ("%24gt", "%24ne", "%24where", "%24regex", "$gt", "$ne")

    def handler(request):
        qs = str(request.url.query)
        body_bytes = request.content if request.content else b""
        body_str = body_bytes.decode("utf-8", errors="ignore")
        if any(s in qs or s in body_str for s in NOSQL_SIGNALS):
            return httpx.Response(500, text=mongo_error)
        # baseline and clean inputs return 200
        return httpx.Response(200, json={"results": []})

    def setup(mock):
        # /api/v1/search is first in PROBE_PATHS — will be in the first 50 surfaces
        mock.get("/api/v1/search").mock(side_effect=handler)
        mock.post("/api/v1/search").mock(side_effect=handler)

    findings = await run_plugin(InjectionPlugin, target, setup)
    nosql = [f for f in findings if "nosql" in f.title.lower() or "injection" in f.title.lower()]
    assert len(nosql) >= 1, f"Expected NoSQL injection finding, got: {[f.title for f in findings]}"


@pytest.mark.asyncio
async def test_injection_clean_consistent_responses(target):
    """API returns consistent 200 for all inputs → no CRITICAL findings."""
    def setup(mock):
        # Only /api/v1/search responds (to avoid being skipped by preflight)
        # It always returns 200 with the same response regardless of payload
        mock.get("/api/v1/search").mock(
            return_value=httpx.Response(200, json={"results": []})
        )

    findings = await run_plugin(InjectionPlugin, target, setup)
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) == 0, f"Clean API should have no CRITICAL findings, got: {[f.title for f in critical]}"


# ── BOLA Tests ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_bola_sequential_ids_probable(target):
    """Single-user: GET /api/v1/users/1 returns data → PROBABLE finding."""
    def setup(mock):
        mock.get("/api/v1/users/1").mock(return_value=httpx.Response(
            200, json={"id": 1, "email": "user1@example.com", "name": "User One"}
        ))

    findings = await run_plugin(BOLAPlugin, target, setup)
    assert len(findings) >= 1
    assert any(f.status == FindingStatus.PROBABLE for f in findings)


@pytest.mark.asyncio
async def test_bola_confirmed_both_users_access(target_dual):
    """Dual-user: both User A and User B can access resource /api/v1/users/1 → CONFIRMED."""
    def user_handler(request):
        # Both user A and user B tokens can access user 1's data
        auth = request.headers.get("Authorization", "")
        if "userA_token" in auth or "userB_token" in auth:
            return httpx.Response(200, json={
                "id": 1, "email": "userA@example.com", "ssn": "123-45-6789"
            })
        return httpx.Response(403)

    def setup(mock):
        mock.get("/api/v1/users/1").mock(side_effect=user_handler)

    findings = await run_plugin(BOLAPlugin, target_dual, setup)
    confirmed = [f for f in findings if f.status == FindingStatus.CONFIRMED]
    assert len(confirmed) >= 1, f"Expected CONFIRMED BOLA, got: {[f.title for f in findings]}"


@pytest.mark.asyncio
async def test_bola_authorization_enforced(target_dual):
    """Dual-user: User B gets 403 → no CONFIRMED BOLA finding."""
    def user_handler(request):
        auth = request.headers.get("Authorization", "")
        if "userA_token" in auth:
            return httpx.Response(200, json={"id": 1, "email": "userA@example.com"})
        return httpx.Response(403, json={"error": "Forbidden"})

    def setup(mock):
        mock.get("/api/v1/users/1").mock(side_effect=user_handler)

    findings = await run_plugin(BOLAPlugin, target_dual, setup)
    confirmed = [f for f in findings if f.status == FindingStatus.CONFIRMED]
    assert len(confirmed) == 0, "No CONFIRMED BOLA when authorization enforced"
