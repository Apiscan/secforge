"""Tests for API key entropy and pattern detection."""

import pytest
import respx
import httpx

from secforge.plugins.rest.apikey import APIKeyPlugin, _shannon_entropy, _analyze_key
from secforge.models.target import TargetConfig, AuthConfig, ScopeConfig
from secforge.models.enums import Severity, FindingStatus
from secforge.core.client import SecForgeClient


@pytest.fixture
def make_target():
    def _make(auth_type="api_key", key_value="testkey"):
        return TargetConfig(
            url="https://api.example.com",
            auth=AuthConfig(type=auth_type, value=key_value, header="X-API-Key"),
            scope=ScopeConfig(authorized=True, acknowledged_by="Test"),
        )
    return _make


def test_shannon_entropy_random():
    """High-entropy string should score well."""
    entropy = _shannon_entropy("XKj9mN2pQr8vWxYzA3cFhLsEuTbDiOg1")
    assert entropy > 4.0, f"Expected high entropy, got {entropy}"


def test_shannon_entropy_low():
    """Repeated characters = low entropy."""
    entropy = _shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaa")
    assert entropy == 0.0


def test_low_entropy_api_key_flagged(make_target):
    """Very short/low-entropy key should be flagged HIGH."""
    target = make_target(key_value="abc123")
    findings = _analyze_key("abc123", "test header", target)
    high_findings = [f for f in findings if f.severity == Severity.HIGH and "Entropy" in f.title]
    assert high_findings, f"Should flag low entropy key. Got: {[f.title for f in findings]}"


def test_test_key_flagged(make_target):
    """Key containing 'test' should be flagged HIGH."""
    target = make_target(key_value="sk-test-abc123def456ghi789")
    findings = _analyze_key("sk-test-abc123def456ghi789", "test header", target)
    test_findings = [f for f in findings if "Test" in f.title or "Placeholder" in f.title]
    assert test_findings, "Should detect test key"
    assert test_findings[0].severity == Severity.HIGH


def test_strong_key_no_high_findings(make_target):
    """High-entropy key with no test patterns = no HIGH findings."""
    strong_key = "XKj9mN2pQr8vWxYzA3cFhLsEuTbDiOg1ABCDEF"
    target = make_target(key_value=strong_key)
    findings = _analyze_key(strong_key, "X-API-Key header", target)
    high_findings = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert not high_findings, f"Strong key should not produce HIGH findings: {[f.title for f in high_findings]}"


@pytest.mark.asyncio
async def test_plugin_runs_with_api_key(make_target):
    """Full plugin run with API key target."""
    plugin = APIKeyPlugin()
    target = make_target(key_value="sk-test-shortkey")

    with respx.mock(base_url="https://api.example.com", assert_all_mocked=False) as mock:
        mock.get("/").mock(return_value=httpx.Response(200, json={"status": "ok"}))

        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    assert findings, "Should produce at least one finding for test/short key"
    severities = [f.severity for f in findings]
    assert Severity.HIGH in severities or Severity.CRITICAL in severities
