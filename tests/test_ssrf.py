"""Tests for SSRF plugin."""

from __future__ import annotations

import pytest
import respx
import httpx

from secforge.plugins.rest.ssrf import SSRFPlugin
from secforge.models.target import TargetConfig, ScopeConfig, AuthConfig, ScanOptions
from secforge.core.client import SecForgeClient

BASE = "https://api.example.com"


@pytest.fixture
def target() -> TargetConfig:
    return TargetConfig(
        url=BASE,
        name="test",
        scope=ScopeConfig(authorized=True, acknowledged_by="test"),
        auth=AuthConfig(),
        options=ScanOptions(verify_ssl=False, rate_limit=100),
    )


@pytest.mark.asyncio
async def test_cloud_metadata_canary_in_response(target):
    """Server echoes cloud metadata canary — CONFIRMED CRITICAL."""
    plugin = SSRFPlugin()

    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        # All requests return a cloud metadata body
        mock.get(url__regex=r".*").mock(
            return_value=httpx.Response(200, text='{"ami-id": "ami-12345678", "instance-id": "i-abc"}')
        )
        mock.post(url__regex=r".*").mock(return_value=httpx.Response(404, text="not found"))

        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    crits = [f for f in findings if f.severity.value == "CRITICAL" and "Cloud Metadata" in f.title]
    assert len(crits) >= 1
    assert crits[0].status.value == "CONFIRMED"
    assert crits[0].evidence


@pytest.mark.asyncio
async def test_ssrf_error_signal_in_response(target):
    """Server returns 'connection refused' — proves it tried to fetch the URL."""
    plugin = SSRFPlugin()

    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        mock.get(url__regex=r".*").mock(
            return_value=httpx.Response(500, text="Error: connection refused while fetching http://169.254.169.254")
        )
        mock.post(url__regex=r".*").mock(return_value=httpx.Response(404, text="not found"))

        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    high = [f for f in findings if f.severity.value == "HIGH"]
    assert len(high) >= 1
    assert "SSRF" in high[0].title


@pytest.mark.asyncio
async def test_open_redirect_detected(target):
    """Server reflects redirect param into Location header — open redirect."""
    plugin = SSRFPlugin()

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "evil-attacker.com" in url:
            return httpx.Response(302, headers={"Location": "http://evil-attacker.com/"})
        return httpx.Response(404, text="not found")

    with respx.mock(base_url=BASE) as mock:
        mock.get(url__regex=r".*").mock(side_effect=handler)
        mock.post(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    redirects = [f for f in findings if "Open Redirect" in f.title]
    assert len(redirects) >= 1
    assert redirects[0].status.value == "CONFIRMED"


@pytest.mark.asyncio
async def test_proxy_endpoint_detected(target):
    """/api/proxy returns 200 — flagged for manual SSRF testing."""
    plugin = SSRFPlugin()

    def handler(request: httpx.Request) -> httpx.Response:
        if "/api/proxy" in str(request.url):
            return httpx.Response(200, text="proxy ready")
        return httpx.Response(404, text="not found")

    with respx.mock(base_url=BASE) as mock:
        mock.get(url__regex=r".*").mock(side_effect=handler)
        mock.post(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    proxy_findings = [f for f in findings if "Proxy" in f.title or "Fetch Endpoint" in f.title]
    assert len(proxy_findings) >= 1


@pytest.mark.asyncio
async def test_no_ssrf_on_clean_api(target):
    """A clean API returning 404 everywhere has no CRITICAL findings."""
    plugin = SSRFPlugin()

    with respx.mock(base_url=BASE) as mock:
        mock.get(url__regex=r".*").mock(return_value=httpx.Response(404, text="not found"))
        mock.post(url__regex=r".*").mock(return_value=httpx.Response(404, text="not found"))

        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    crits = [f for f in findings if f.severity.value == "CRITICAL"]
    assert len(crits) == 0
