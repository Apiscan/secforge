"""Tests for JWT security plugin."""

import base64
import hashlib
import hmac
import json
import time
import pytest
import respx
import httpx

from secforge.plugins.rest.jwt import JWTPlugin, _forge_token, _brute_force_secret
from secforge.models.target import TargetConfig, AuthConfig, ScopeConfig
from secforge.models.enums import Severity, FindingStatus


def make_jwt(header: dict, payload: dict, secret: str = "secret", alg: str = "HS256") -> str:
    """Helper: build a real HS256-signed JWT."""
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()
    h, p = b64(header), b64(payload)
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{h}.{p}.{sig_b64}"


@pytest.fixture
def weak_jwt_target():
    token = make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "1", "exp": int(time.time()) + 3600 * 48},  # 48h — long TTL
        secret="secret",
    )
    return TargetConfig(
        url="https://api.example.com",
        auth=AuthConfig(type="bearer", token=token),
        scope=ScopeConfig(authorized=True, acknowledged_by="Test"),
    )


@pytest.fixture
def no_exp_jwt_target():
    token = make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "1", "admin": True},  # No exp
        secret="strongrandomsecret123456789012345",
    )
    return TargetConfig(
        url="https://api.example.com",
        auth=AuthConfig(type="bearer", token=token),
        scope=ScopeConfig(authorized=True, acknowledged_by="Test"),
    )


@pytest.mark.asyncio
async def test_weak_secret_detected(weak_jwt_target):
    """Weak HS256 secret 'secret' should be brute-forced."""
    plugin = JWTPlugin()

    with respx.mock(base_url="https://api.example.com", assert_all_mocked=False):
        from secforge.core.client import SecForgeClient
        async with SecForgeClient(weak_jwt_target) as client:
            findings = await plugin.run(weak_jwt_target, client)

    weak_findings = [f for f in findings if "Weak Secret" in f.title]
    assert weak_findings, f"Should detect weak secret. Got: {[f.title for f in findings]}"
    assert weak_findings[0].severity == Severity.CRITICAL
    assert "secret" in weak_findings[0].title


@pytest.mark.asyncio
async def test_no_exp_claim_flagged(no_exp_jwt_target):
    """JWT without exp claim should produce HIGH finding."""
    plugin = JWTPlugin()

    with respx.mock(base_url="https://api.example.com", assert_all_mocked=False):
        from secforge.core.client import SecForgeClient
        async with SecForgeClient(no_exp_jwt_target) as client:
            findings = await plugin.run(no_exp_jwt_target, client)

    exp_findings = [f for f in findings if "Expiry" in f.title or "exp" in f.title.lower()]
    assert exp_findings, "Should flag missing exp claim"
    assert exp_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_long_ttl_flagged(weak_jwt_target):
    """48h TTL should produce LOW finding."""
    plugin = JWTPlugin()

    with respx.mock(base_url="https://api.example.com", assert_all_mocked=False):
        from secforge.core.client import SecForgeClient
        async with SecForgeClient(weak_jwt_target) as client:
            findings = await plugin.run(weak_jwt_target, client)

    ttl_findings = [f for f in findings if "Long Expiry" in f.title or "TTL" in f.title.lower()]
    assert ttl_findings, "Should flag 48h token TTL"
    assert ttl_findings[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_no_bearer_token_skips_gracefully():
    """Non-bearer auth should return empty findings."""
    plugin = JWTPlugin()
    target = TargetConfig(
        url="https://api.example.com",
        scope=ScopeConfig(authorized=True, acknowledged_by="Test"),
    )

    with respx.mock(base_url="https://api.example.com", assert_all_mocked=False):
        from secforge.core.client import SecForgeClient
        async with SecForgeClient(target) as client:
            findings = await plugin.run(target, client)

    assert findings == [], "No JWT = no findings"


def test_brute_force_helper():
    """Unit test the brute-force function directly."""
    token = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, secret="admin")
    parts = token.split(".")
    found = _brute_force_secret(parts, "HS256")
    assert found == "admin"


def test_brute_force_strong_secret_not_found():
    """Strong secret should not be found in the wordlist."""
    token = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1"},
                     secret="XKj9mN2pQr8vWxYzA3cFhLsEuTbDiOg1")
    parts = token.split(".")
    found = _brute_force_secret(parts, "HS256")
    assert found is None
