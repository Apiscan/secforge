"""
Tests for Phase 8 plugins:
  - business_logic (OWASP API6:2023)
  - inventory      (OWASP API9:2023)
  - unsafe_consumption (OWASP API10:2023)
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from secforge.plugins.rest.business_logic import BusinessLogicPlugin
from secforge.plugins.rest.inventory import InventoryPlugin
from secforge.plugins.rest.unsafe_consumption import UnsafeConsumptionPlugin
from secforge.models.enums import Severity, FindingStatus


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_response(status: int, body: str = "", headers: dict | None = None) -> httpx.Response:
    return httpx.Response(
        status_code=status,
        content=body.encode(),
        headers=headers or {"content-type": "application/json"},
        request=httpx.Request("GET", "https://api.example.com/"),
    )


def make_target(url: str = "https://api.example.com") -> MagicMock:
    target = MagicMock()
    target.url = url
    target.auth = None
    return target


def make_client() -> MagicMock:
    client = MagicMock()
    client._client = AsyncMock()
    return client


# ══════════════════════════════════════════════════════════════════════════════
# BusinessLogicPlugin Tests
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_business_logic_rate_limit_missing():
    """No 429 on 8 rapid POSTs to a login endpoint → HIGH finding."""
    plugin = BusinessLogicPlugin()
    target = make_target()
    client = make_client()

    ok_resp = make_response(200, '{"status":"ok"}')
    # Simulate endpoint exists (OPTIONS → 200) and no 429 on burst
    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_cls.return_value.__aexit__.return_value = AsyncMock(return_value=False)

        mock_http.options.return_value = make_response(200)
        mock_http.get.return_value = make_response(200)
        mock_http.post.return_value = ok_resp

        findings = await plugin.run(target, client)

    rate_findings = [f for f in findings if "Rate Limiting" in f.title]
    assert len(rate_findings) > 0, "Should detect missing rate limit on business flow"
    assert rate_findings[0].severity in (Severity.HIGH, Severity.CRITICAL)
    assert rate_findings[0].status == FindingStatus.CONFIRMED
    assert rate_findings[0].owasp_id == "API6:2023"


@pytest.mark.asyncio
async def test_business_logic_rate_limit_present():
    """429 returned → no rate-limit finding."""
    plugin = BusinessLogicPlugin()
    target = make_target()
    client = make_client()

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_cls.return_value.__aexit__.return_value = AsyncMock(return_value=False)

        mock_http.options.return_value = make_response(200)
        mock_http.get.return_value = make_response(200)
        # Burst returns 429
        mock_http.post.return_value = make_response(429, '{"error":"too many requests"}')

        findings = await plugin.run(target, client)

    rate_findings = [f for f in findings if "Rate Limiting" in f.title]
    assert len(rate_findings) == 0, "No finding when 429 is returned"


@pytest.mark.asyncio
async def test_business_logic_account_enumeration():
    """Different status codes for known vs unknown email → enumeration finding."""
    plugin = BusinessLogicPlugin()
    target = make_target()
    client = make_client()

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_cls.return_value.__aexit__.return_value = AsyncMock(return_value=False)

        # Unknown email → 404; plausible email → 200
        def post_side_effect(url, **kwargs):
            body = kwargs.get("json", {})
            email = body.get("email", "")
            if "definitely-not-real-xk9z" in email:
                # Different status code (not 404) for unknown email
                return make_response(400, '{"error":"User not found"}')
            return make_response(200, '{"message":"email sent"}')

        mock_http.post.side_effect = post_side_effect
        mock_http.options.return_value = make_response(200)
        mock_http.get.return_value = make_response(200)

        findings = await plugin.run(target, client)

    enum_findings = [f for f in findings if "Enumeration" in f.title]
    assert len(enum_findings) > 0, "Should detect account enumeration via status code difference"
    assert enum_findings[0].severity == Severity.MEDIUM
    assert enum_findings[0].status == FindingStatus.CONFIRMED


@pytest.mark.asyncio
async def test_business_logic_negative_price_accepted():
    """Endpoint accepts negative financial value with 200 success → CRITICAL."""
    plugin = BusinessLogicPlugin()
    target = make_target()
    client = make_client()

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_cls.return_value.__aexit__.return_value = AsyncMock(return_value=False)

        mock_http.options.return_value = make_response(404)
        mock_http.get.return_value = make_response(404)

        # Financial endpoint accepts negative
        def post_side_effect(url, **kwargs):
            if "checkout" in url or "cart" in url or "payment" in url or "order" in url:
                return make_response(200, '{"success":true,"order_id":"123","confirmed":true}')
            return make_response(404)

        mock_http.post.side_effect = post_side_effect

        findings = await plugin.run(target, client)

    price_findings = [f for f in findings if "Negative" in f.title or "Manipulation" in f.title]
    assert len(price_findings) > 0, "Should detect negative price accepted"
    assert price_findings[0].severity == Severity.CRITICAL


# ══════════════════════════════════════════════════════════════════════════════
# InventoryPlugin Tests
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_inventory_old_version_auth_bypass():
    """Old /v1 endpoint returns data without auth but /v2 requires auth → CRITICAL."""
    plugin = InventoryPlugin()
    target = make_target("https://api.example.com/api/v2/users/me")
    client = make_client()

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_cls.return_value.__aexit__.return_value = AsyncMock(return_value=False)

        def get_side_effect(url, **kwargs):
            headers = kwargs.get("headers", {})
            has_auth = bool(headers)
            if "/v1/" in url:
                # v1 always returns 200 regardless of auth
                return make_response(200, '{"user_id":"123","email":"test@example.com"}')
            elif "/v2/" in url:
                if has_auth:
                    return make_response(200, '{"user_id":"123"}')
                return make_response(401, '{"error":"Unauthorized"}')
            return make_response(404)

        mock_http.get.side_effect = get_side_effect

        findings = await plugin.run(target, client)

    bypass_findings = [f for f in findings if "Auth Bypass" in f.title]
    assert len(bypass_findings) > 0, "Should detect old version auth bypass"
    assert bypass_findings[0].severity == Severity.CRITICAL
    assert bypass_findings[0].owasp_id == "API9:2023"


@pytest.mark.asyncio
async def test_inventory_doc_exposure():
    """Swagger UI accessible in production → MEDIUM finding."""
    plugin = InventoryPlugin()
    target = make_target()
    client = make_client()

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_cls.return_value.__aexit__.return_value = AsyncMock(return_value=False)

        def get_side_effect(url, **kwargs):
            if "swagger" in url.lower() or "api-docs" in url.lower():
                return make_response(200, '{"openapi":"3.0.0","info":{"title":"API"},"paths":{}}')
            return make_response(404)

        mock_http.get.side_effect = get_side_effect

        findings = await plugin.run(target, client)

    doc_findings = [f for f in findings if "Documentation" in f.title]
    assert len(doc_findings) > 0, "Should detect API docs exposed in production"
    assert doc_findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_inventory_clean():
    """All endpoints return 404 → no findings."""
    plugin = InventoryPlugin()
    target = make_target()
    client = make_client()

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_cls.return_value.__aexit__.return_value = AsyncMock(return_value=False)
        mock_http.get.return_value = make_response(404)

        findings = await plugin.run(target, client)

    assert len(findings) == 0, "No findings on clean API"


# ══════════════════════════════════════════════════════════════════════════════
# UnsafeConsumptionPlugin Tests
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_unsafe_consumption_open_redirect():
    """GET ?redirect=https://evil.apiscan.ai → 302 to evil host → HIGH finding."""
    plugin = UnsafeConsumptionPlugin()
    target = make_target()
    client = make_client()

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_cls.return_value.__aexit__.return_value = AsyncMock(return_value=False)

        def get_side_effect(url, **kwargs):
            if "evil.apiscan.ai" in url:
                return make_response(
                    302, "",
                    headers={"location": "https://evil.apiscan.ai/redirect-check"}
                )
            return make_response(404)

        mock_http.get.side_effect = get_side_effect
        mock_http.post.return_value = make_response(404)

        findings = await plugin.run(target, client)

    redirect_findings = [f for f in findings if "Redirect" in f.title]
    assert len(redirect_findings) > 0, "Should detect open redirect"
    assert redirect_findings[0].severity == Severity.HIGH
    assert redirect_findings[0].owasp_id == "API10:2023"


@pytest.mark.asyncio
async def test_unsafe_consumption_clean():
    """All endpoints return 404 → no findings."""
    plugin = UnsafeConsumptionPlugin()
    target = make_target()
    client = make_client()

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_cls.return_value.__aexit__.return_value = AsyncMock(return_value=False)
        mock_http.get.return_value = make_response(404)
        mock_http.post.return_value = make_response(404)

        findings = await plugin.run(target, client)

    assert len(findings) == 0, "No findings on clean API"


# ── Plugin registry ───────────────────────────────────────────────────────────

def test_all_plugins_registered():
    """All 19 plugins are in the registry."""
    from secforge.plugins import ALL_PLUGINS
    assert "business_logic" in ALL_PLUGINS
    assert "inventory" in ALL_PLUGINS
    assert "unsafe_consumption" in ALL_PLUGINS
    assert len(ALL_PLUGINS) == 19, f"Expected 19 plugins, got {len(ALL_PLUGINS)}"


def test_new_plugins_have_correct_owasp_ids():
    """New plugins have correct OWASP API Top 10 2023 IDs."""
    assert BusinessLogicPlugin.owasp_id == "API6:2023"
    assert InventoryPlugin.owasp_id == "API9:2023"
    assert UnsafeConsumptionPlugin.owasp_id == "API10:2023"
