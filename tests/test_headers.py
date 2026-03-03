"""Tests for the HTTP security headers plugin."""

import pytest
import respx
import httpx

from secforge.plugins.rest.headers import HeadersPlugin
from secforge.models.target import TargetConfig, ScopeConfig
from secforge.models.enums import Severity, FindingStatus
from secforge.core.client import SecForgeClient


@pytest.fixture
def secure_target():
    return TargetConfig(
        url="https://api.example.com",
        name="Test Target",
        scope=ScopeConfig(authorized=True, acknowledged_by="Test"),
    )


@pytest.fixture
def http_target():
    return TargetConfig(url="http://api.example.com", name="HTTP Target")


@pytest.mark.asyncio
async def test_missing_all_security_headers(secure_target):
    """Server with no security headers should generate multiple findings."""
    plugin = HeadersPlugin()

    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/").mock(return_value=httpx.Response(200, text="OK"))

        async with SecForgeClient(secure_target) as client:
            findings = await plugin.run(secure_target, client)

    titles = [f.title for f in findings]
    assert any("HSTS" in t for t in titles), "Should flag missing HSTS"
    assert any("X-Content-Type" in t for t in titles), "Should flag missing X-Content-Type-Options"
    assert all(f.status == FindingStatus.CONFIRMED for f in findings)
    assert all(f.evidence for f in findings), "Every finding must have evidence"


@pytest.mark.asyncio
async def test_all_headers_present(secure_target):
    """Server with all security headers should return only INFO findings (disclosures)."""
    plugin = HeadersPlugin()

    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'none'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }

    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/").mock(return_value=httpx.Response(200, headers=headers, text="OK"))

        async with SecForgeClient(secure_target) as client:
            findings = await plugin.run(secure_target, client)

    # Only INFO findings (no missing required headers)
    non_info = [f for f in findings if f.severity != Severity.INFO]
    assert not non_info, f"Expected no non-INFO findings, got: {[f.title for f in non_info]}"


@pytest.mark.asyncio
async def test_server_version_disclosure(secure_target):
    """Server header with version string should be flagged."""
    plugin = HeadersPlugin()

    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/").mock(return_value=httpx.Response(
            200,
            headers={"Server": "nginx/1.24.0"},
            text="OK",
        ))

        async with SecForgeClient(secure_target) as client:
            findings = await plugin.run(secure_target, client)

    server_findings = [f for f in findings if "Server" in f.title]
    assert server_findings, "Should detect Server header disclosure"
    assert server_findings[0].severity == Severity.INFO


@pytest.mark.asyncio
async def test_hsts_skipped_on_http(http_target):
    """HSTS check should be skipped for HTTP targets."""
    plugin = HeadersPlugin()

    with respx.mock(base_url="http://api.example.com") as mock:
        mock.get("/").mock(return_value=httpx.Response(200, text="OK"))

        async with SecForgeClient(http_target) as client:
            findings = await plugin.run(http_target, client)

    hsts_findings = [f for f in findings if "HSTS" in f.title]
    assert not hsts_findings, "HSTS should not be checked on HTTP targets"


@pytest.mark.asyncio
async def test_finding_evidence_contract(secure_target):
    """All CONFIRMED findings must have at least one evidence with response_status."""
    plugin = HeadersPlugin()

    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/").mock(return_value=httpx.Response(200, text="OK"))

        async with SecForgeClient(secure_target) as client:
            findings = await plugin.run(secure_target, client)

    for f in findings:
        if f.status == FindingStatus.CONFIRMED:
            assert f.evidence, f"Finding '{f.title}' is CONFIRMED but has no evidence"
            has_response = any(e.response_status is not None for e in f.evidence)
            assert has_response, f"Finding '{f.title}' CONFIRMED but evidence has no response_status"
