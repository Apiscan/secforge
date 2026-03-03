"""Tests for CORS misconfiguration plugin."""

import pytest
import respx
import httpx

from secforge.plugins.rest.cors import CORSPlugin, EVIL_ORIGIN
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
async def test_arbitrary_origin_with_credentials(target):
    """Reflected origin + ACAC:true = CRITICAL."""
    plugin = CORSPlugin()

    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/").mock(return_value=httpx.Response(
            200,
            headers={
                "Access-Control-Allow-Origin": EVIL_ORIGIN,
                "Access-Control-Allow-Credentials": "true",
            },
            text="{}",
        ))

        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    assert findings, "Should detect CORS vulnerability"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].status == FindingStatus.CONFIRMED
    assert "Credentials" in findings[0].title


@pytest.mark.asyncio
async def test_arbitrary_origin_no_credentials(target):
    """Reflected origin without credentials = MEDIUM."""
    plugin = CORSPlugin()

    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/").mock(return_value=httpx.Response(
            200,
            headers={"Access-Control-Allow-Origin": EVIL_ORIGIN},
            text="{}",
        ))

        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    cors_findings = [f for f in findings if "Reflected" in f.title or "Arbitrary" in f.title]
    assert cors_findings
    assert cors_findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_null_origin_accepted(target):
    """Null origin accepted = MEDIUM."""
    plugin = CORSPlugin()

    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/").mock(return_value=httpx.Response(
            200,
            headers={"Access-Control-Allow-Origin": "null"},
            text="{}",
        ))

        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    null_findings = [f for f in findings if "Null" in f.title or "null" in f.title.lower()]
    assert null_findings, "Should detect null origin acceptance"


@pytest.mark.asyncio
async def test_secure_cors_no_findings(target):
    """Strict CORS policy should produce no findings."""
    plugin = CORSPlugin()

    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/").mock(return_value=httpx.Response(
            200,
            headers={"Access-Control-Allow-Origin": "https://app.example.com"},
            text="{}",
        ))

        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    # Specific origin = no CORS vuln
    vuln_findings = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert not vuln_findings, f"Should not flag secure CORS: {[f.title for f in vuln_findings]}"
