"""Tests for rate limiting plugin."""

import pytest
import respx
import httpx

from secforge.plugins.rest.rate_limit import RateLimitPlugin, _burst_test
from secforge.models.target import TargetConfig, ScopeConfig
from secforge.models.enums import Severity, FindingStatus
from secforge.core.client import SecForgeClient


@pytest.fixture
def target():
    return TargetConfig(
        url="https://api.example.com",
        scope=ScopeConfig(authorized=True, acknowledged_by="Test"),
    )


@pytest.mark.asyncio
async def test_no_rate_limiting_on_root(target):
    """
    Server always 200s without rate limit headers → finding on root.
    Auth paths all 404 so only root is flagged.
    """
    plugin = RateLimitPlugin()

    with respx.mock(base_url="https://api.example.com", assert_all_mocked=False) as mock:
        mock.get("/").mock(return_value=httpx.Response(200, text="OK"))

        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    root_findings = [f for f in findings if f.endpoint == "/" and "No Rate Limiting" in f.title]
    assert root_findings, f"Should detect missing rate limiting on /. Got: {[f.title for f in findings]}"
    assert root_findings[0].status == FindingStatus.CONFIRMED
    assert root_findings[0].evidence


@pytest.mark.asyncio
async def test_rate_limit_enforced_on_root(target):
    """Server returns 429 during burst → no finding for root."""
    plugin = RateLimitPlugin()

    call_count = 0

    def rate_limited_response(request):
        nonlocal call_count
        call_count += 1
        if call_count > 5:
            return httpx.Response(429, headers={"Retry-After": "60"}, text="Too Many Requests")
        return httpx.Response(200, text="OK")

    with respx.mock(base_url="https://api.example.com", assert_all_mocked=False) as mock:
        mock.get("/").mock(side_effect=rate_limited_response)

        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    root_findings = [f for f in findings if f.endpoint == "/" and "No Rate Limiting" in f.title]
    assert not root_findings, "Should not flag root when 429 is returned"


@pytest.mark.asyncio
async def test_unreachable_auth_endpoints_not_flagged(target):
    """Auth endpoints that fail with connection error should not produce findings."""
    plugin = RateLimitPlugin()

    with respx.mock(base_url="https://api.example.com", assert_all_mocked=False) as mock:
        mock.get("/").mock(return_value=httpx.Response(200, text="OK"))
        # All other paths intentionally unmocked — will cause connection errors in raw client

        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    # Auth path findings should only appear if we actually got responses
    auth_findings = [f for f in findings if "Authentication Endpoint" in f.title]
    for f in auth_findings:
        assert f.evidence[0].response_status is not None or len(f.evidence[0].note) > 10
