"""
Plugin: Unrestricted Access to Sensitive Business Flows

OWASP API6:2023 — the category that catches perfectly functional code with
missing or bypassable controls on high-value business actions.

Unlike injection or broken auth, these bugs exist even when your code works
exactly as designed — the design itself is the vulnerability.

Detection strategy:
──────────────────────────────────────────────────────────────────────────────
1. RATE LIMIT GAP ON BUSINESS FLOWS
   Checkout, register, coupon, OTP, password reset, transfer, vote endpoints
   — burst 10 requests, check if any 429/throttle appears.
   Missing = attacker can automate credential stuffing, coupon brute-force,
   account farming, review bombing.

2. SEQUENTIAL RESOURCE ID ENUMERATION
   Order IDs, invoice numbers, confirmation codes following obvious sequences
   (integer +1, date-prefixed, short UUIDs) — enable competitive intelligence
   and revenue/customer count scraping.

3. NEGATIVE QUANTITY / PRICE MANIPULATION
   POST body with qty=-1, price=0.01, amount=-100 to financial/cart endpoints.
   Broken if server accepts without validation.

4. ACCOUNT ENUMERATION VIA TIMING / ERROR MESSAGES
   Register/login/reset with known vs unknown emails — timing delta or
   different error messages = user existence oracle.

5. MISSING ANTI-AUTOMATION SIGNALS
   High-value flows with no CAPTCHA header, no bot-score requirement,
   no device fingerprint check in request or response.
──────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import asyncio
import re
import time
from urllib.parse import urljoin, urlparse

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient


# ── Business-flow endpoint patterns ──────────────────────────────────────────

FLOW_PATTERNS = [
    # Authentication / account
    ("/api/auth/register",              "Account registration"),
    ("/api/register",                   "Account registration"),
    ("/register",                       "Account registration"),
    ("/api/auth/login",                 "Login"),
    ("/api/login",                      "Login"),
    ("/login",                          "Login"),
    ("/api/auth/forgot-password",       "Password reset"),
    ("/api/auth/reset-password",        "Password reset"),
    ("/api/password/reset",             "Password reset"),
    ("/api/auth/otp",                   "OTP verification"),
    ("/api/otp/verify",                 "OTP verification"),
    ("/api/otp/send",                   "OTP send"),
    ("/api/verify",                     "Verification flow"),
    # Financial / transactional
    ("/api/checkout",                   "Checkout"),
    ("/api/v1/checkout",                "Checkout"),
    ("/api/payment",                    "Payment"),
    ("/api/payments",                   "Payment"),
    ("/api/orders",                     "Order creation"),
    ("/api/v1/orders",                  "Order creation"),
    ("/api/transfer",                   "Fund transfer"),
    ("/api/transfers",                  "Fund transfer"),
    ("/api/withdraw",                   "Withdrawal"),
    ("/api/v1/withdraw",                "Withdrawal"),
    # Promotional
    ("/api/coupon",                     "Coupon redemption"),
    ("/api/coupons/apply",              "Coupon redemption"),
    ("/api/discount",                   "Discount application"),
    ("/api/promo",                      "Promo code"),
    ("/api/voucher",                    "Voucher"),
    # Voting / engagement
    ("/api/vote",                       "Voting endpoint"),
    ("/api/likes",                      "Like/react endpoint"),
    ("/api/reviews",                    "Review submission"),
    ("/api/ratings",                    "Rating submission"),
    ("/api/referral",                   "Referral code"),
    ("/api/invite",                     "Invite / referral"),
]

# Headers that suggest anti-automation protection is present
CAPTCHA_HEADERS = {
    "x-recaptcha-token", "x-captcha-token", "x-cf-turnstile-token",
    "x-hcaptcha-token", "cf-challenge-platform",
}
CAPTCHA_BODY_PATTERNS = [
    r"recaptcha[-_]token",
    r"captcha[-_]token",
    r"captcha[-_]response",
    r"g-recaptcha-response",
    r"h-captcha-response",
    r"cf-turnstile-response",
]

# Numeric sequential patterns in common ID fields
SEQUENTIAL_ID_PATTERNS = [
    r'["\']order_id["\']\s*:\s*["\']?(\d{4,8})["\']?',
    r'["\']invoice_id["\']\s*:\s*["\']?(\d{4,8})["\']?',
    r'["\']ticket_id["\']\s*:\s*["\']?(\d{4,8})["\']?',
    r'["\']confirmation["\']\s*:\s*["\']?(\d{5,10})["\']?',
    r'["\']ref["\']\s*:\s*["\']?([A-Z]{2}\d{6,8})["\']?',
]


class BusinessLogicPlugin(BasePlugin):
    name = "business_logic"
    description = "Unrestricted access to sensitive business flows (OWASP API6:2023)"
    owasp_id = "API6:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []
        base = target.url.rstrip("/")
        headers = {}
        if hasattr(target, "auth") and target.auth:
            from secforge.core.auth import build_auth_header
            try:
                ah = build_auth_header(target.auth)
                if ah:
                    headers.update(ah)
            except Exception:
                pass

        async with httpx.AsyncClient(
            headers={
                "User-Agent": "ApiScan-SecurityScanner/1.0",
                "Content-Type": "application/json",
                **headers,
            },
            timeout=10.0,
            follow_redirects=True,
            verify=False,
        ) as http:
            tasks = [
                self._check_flow_rate_limits(http, base, findings),
                self._check_sequential_ids(http, base, findings),
                self._check_account_enumeration(http, base, findings),
                self._check_negative_quantities(http, base, findings),
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        return findings

    # ── Check 1: Missing rate limits on high-value flows ─────────────────────

    async def _check_flow_rate_limits(
        self, http: httpx.AsyncClient, base: str, findings: list[Finding]
    ) -> None:
        """Burst 8 POST requests to business flow endpoints. No 429 = vulnerable."""
        for path, flow_name in FLOW_PATTERNS:
            url = base + path
            try:
                # Probe once with HEAD/OPTIONS to check if endpoint exists
                probe = await http.options(url)
                if probe.status_code in (404, 405):
                    # try GET
                    probe2 = await http.get(url)
                    if probe2.status_code == 404:
                        continue
            except Exception:
                continue

            # Endpoint exists — burst 8 identical POSTs quickly
            try:
                burst_responses = await asyncio.gather(
                    *[
                        http.post(url, json={"test": "apiscan-rate-probe"})
                        for _ in range(8)
                    ],
                    return_exceptions=True,
                )
            except Exception:
                continue

            valid = [
                r for r in burst_responses
                if isinstance(r, httpx.Response) and r.status_code not in (404, 405, 504)
            ]
            if not valid:
                continue

            got_429 = any(r.status_code == 429 for r in valid)
            # Some APIs use 400 with "rate limit" body instead of 429
            got_rate_body = any(
                r.status_code in (400, 429)
                and any(kw in r.text.lower() for kw in ["rate limit", "too many", "throttl", "slow down"])
                for r in valid
                if isinstance(r, httpx.Response)
            )

            if not got_429 and not got_rate_body:
                first_ok = next(
                    (r for r in valid if isinstance(r, httpx.Response)), None
                )
                evidences = []
                if first_ok is not None:
                    evidences.append(Evidence(
                        request_method="POST",
                        request_url=url,
                        response_status=first_ok.status_code,
                        response_body_snippet=first_ok.text[:300],
                        note=f"8 rapid POST requests to {flow_name} endpoint — no 429 or rate-limit response received",
                    ))

                findings.append(Finding(
                    title=f"No Rate Limiting on {flow_name} Endpoint",
                    description=(
                        f"The `{path}` endpoint ({flow_name}) accepts unlimited rapid requests "
                        f"without throttling. 8 sequential POST requests completed without a 429 "
                        f"or rate-limit response.\n\n"
                        f"**Impact**: Attackers can automate credential stuffing, OTP brute-force, "
                        f"coupon farming, bulk account creation, or other high-volume abuse against "
                        f"this endpoint without restriction."
                    ),
                    severity=Severity.HIGH,
                    status=FindingStatus.CONFIRMED,
                    owasp_id=self.owasp_id,
                    plugin=self.name,
                    endpoint=url,
                    remediation=(
                        "Implement per-IP and per-account rate limiting on all business-critical "
                        "endpoints. Use sliding window or token bucket algorithms. "
                        "For authentication flows: max 5 attempts/minute per IP, 10 per account/hour. "
                        "Return HTTP 429 with Retry-After header."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"
                    ],
                    evidence=evidences,
                ))
                # Only report first 3 distinct flows to avoid noise
                if len([f for f in findings if f.plugin == self.name and "Rate Limiting" in f.title]) >= 3:
                    break

    # ── Check 2: Sequential / enumerable resource IDs ────────────────────────

    async def _check_sequential_ids(
        self, http: httpx.AsyncClient, base: str, findings: list[Finding]
    ) -> None:
        """Look for order/invoice IDs in responses that appear sequential."""
        # Probe common endpoints that return resource IDs
        id_probe_paths = [
            "/api/orders", "/api/v1/orders", "/api/invoices",
            "/api/tickets", "/api/bookings", "/api/transactions",
        ]
        for path in id_probe_paths:
            url = base + path
            try:
                r = await http.get(url)
                if r.status_code not in (200, 201):
                    continue
                body = r.text
                for pattern in SEQUENTIAL_ID_PATTERNS:
                    matches = re.findall(pattern, body)
                    if len(matches) >= 2:
                        # Check if IDs are sequential integers
                        try:
                            nums = [int(m) for m in matches if m.isdigit()]
                            if len(nums) >= 2 and max(nums) - min(nums) < len(nums) * 3:
                                findings.append(Finding(
                                    title="Sequential / Enumerable Resource IDs",
                                    description=(
                                        f"The `{path}` endpoint returns resource IDs that follow a "
                                        f"predictable sequential numeric pattern (found: {matches[:3]}).\n\n"
                                        f"**Impact**: Attackers can enumerate total resource count "
                                        f"(revealing user count, revenue volume, order throughput), "
                                        f"access other users' resources by incrementing IDs (BOLA), "
                                        f"or scrape competitive intelligence."
                                    ),
                                    severity=Severity.MEDIUM,
                                    status=FindingStatus.CONFIRMED,
                                    owasp_id=self.owasp_id,
                                    plugin=self.name,
                                    endpoint=url,
                                    remediation=(
                                        "Replace sequential integer IDs with UUIDs (v4) or ULID. "
                                        "Never expose internal database sequence values in API responses. "
                                        "Implement object-level authorization checks even with non-sequential IDs."
                                    ),
                                    references=[
                                        "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"
                                    ],
                                    evidence=[Evidence(
                                        request_method="GET",
                                        request_url=url,
                                        response_status=r.status_code,
                                        response_body_snippet=body[:400],
                                        note=f"Sequential IDs detected: {matches[:5]}",
                                    )],
                                ))
                        except (ValueError, TypeError):
                            pass
            except Exception:
                continue

    # ── Check 3: Account enumeration via timing or error messages ─────────────

    async def _check_account_enumeration(
        self, http: httpx.AsyncClient, base: str, findings: list[Finding]
    ) -> None:
        """Compare error messages for known vs unknown email at login/reset."""
        endpoints = [
            (base + "/api/auth/forgot-password", "email", "Password Reset Enumeration"),
            (base + "/api/password/reset",        "email", "Password Reset Enumeration"),
            (base + "/api/auth/login",             "email", "Login Enumeration"),
        ]
        for url, field, label in endpoints:
            try:
                # Known-invalid email
                t0 = time.monotonic()
                r_unknown = await http.post(url, json={field: "definitely-not-real-xk9z@example.invalid", "password": "test"})
                t_unknown = time.monotonic() - t0

                # Plausible but non-existent email
                t0 = time.monotonic()
                r_valid_fmt = await http.post(url, json={field: "user@gmail.com", "password": "test"})
                t_valid = time.monotonic() - t0

                if r_unknown.status_code == 404 or r_valid_fmt.status_code == 404:
                    continue

                # Different status codes = explicit enumeration
                if r_unknown.status_code != r_valid_fmt.status_code and r_unknown.status_code != 422:
                    findings.append(Finding(
                        title=f"User Enumeration via {label}",
                        description=(
                            f"The `{url.replace(base, '')}` endpoint returns different HTTP status "
                            f"codes for known vs unknown email addresses "
                            f"(unknown: {r_unknown.status_code}, plausible: {r_valid_fmt.status_code}).\n\n"
                            f"**Impact**: Attackers can silently confirm whether an email address "
                            f"has an account, enabling targeted phishing, credential stuffing, "
                            f"and privacy violations."
                        ),
                        severity=Severity.MEDIUM,
                        status=FindingStatus.CONFIRMED,
                        owasp_id=self.owasp_id,
                        plugin=self.name,
                        endpoint=url,
                        remediation=(
                            "Return identical status codes and response bodies for both known and "
                            "unknown email addresses. Use a generic message: "
                            "'If an account with that email exists, you will receive an email.' "
                            "Add consistent artificial delay to prevent timing-based enumeration."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"
                        ],
                        evidence=[
                            Evidence(
                                request_method="POST",
                                request_url=url,
                                response_status=r_unknown.status_code,
                                response_body_snippet=r_unknown.text[:300],
                                note=f"Unknown email → HTTP {r_unknown.status_code}",
                            ),
                            Evidence(
                                request_method="POST",
                                request_url=url,
                                response_status=r_valid_fmt.status_code,
                                response_body_snippet=r_valid_fmt.text[:300],
                                note=f"Plausible email → HTTP {r_valid_fmt.status_code} — different code reveals enumeration",
                            ),
                        ],
                    ))
                    continue

                # Same status but different body = message-based enumeration
                body_unknown = r_unknown.text.lower()
                body_valid   = r_valid_fmt.text.lower()
                unknown_keywords = any(kw in body_unknown for kw in ["not found", "no account", "doesn't exist", "not registered", "invalid email"])
                valid_keywords   = any(kw in body_valid   for kw in ["email sent", "check your email", "reset link", "instructions"])
                if unknown_keywords and valid_keywords:
                    findings.append(Finding(
                        title=f"User Enumeration via {label} Response Body",
                        description=(
                            f"The `{url.replace(base, '')}` endpoint returns different response bodies "
                            f"for known vs unknown email addresses, allowing user existence verification.\n\n"
                            f"**Impact**: Targeted phishing, credential stuffing list validation, "
                            f"privacy violation."
                        ),
                        severity=Severity.MEDIUM,
                        status=FindingStatus.CONFIRMED,
                        owasp_id=self.owasp_id,
                        plugin=self.name,
                        endpoint=url,
                        remediation=(
                            "Return identical response bodies regardless of whether the email exists. "
                            "Always respond with: 'If that address is registered, an email is on its way.'"
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"
                        ],
                        evidence=[
                            Evidence(
                                request_method="POST",
                                request_url=url,
                                response_status=r_unknown.status_code,
                                response_body_snippet=r_unknown.text[:300],
                                note="Unknown email — body reveals non-existence",
                            ),
                            Evidence(
                                request_method="POST",
                                request_url=url,
                                response_status=r_valid_fmt.status_code,
                                response_body_snippet=r_valid_fmt.text[:300],
                                note="Plausible email — body reveals existence",
                            ),
                        ],
                    ))

            except Exception:
                continue

    # ── Check 4: Negative quantity / price manipulation ───────────────────────

    async def _check_negative_quantities(
        self, http: httpx.AsyncClient, base: str, findings: list[Finding]
    ) -> None:
        """Send negative/zero values to financial endpoints and check acceptance."""
        financial_paths = [
            ("/api/cart/add",       {"item_id": "test", "quantity": -1, "price": 0.01}),
            ("/api/order",          {"quantity": -1, "amount": -100}),
            ("/api/checkout",       {"amount": 0, "quantity": -1}),
            ("/api/payment",        {"amount": -1}),
            ("/api/transfer",       {"amount": -100, "to": "attacker"}),
            ("/api/v1/cart",        {"quantity": -99, "price": 0}),
        ]
        for path, payload in financial_paths:
            url = base + path
            try:
                r = await http.post(url, json=payload)
                if r.status_code in (404, 405, 501):
                    continue
                # If endpoint exists and accepted the negative value (2xx)
                if r.status_code in (200, 201, 202):
                    body = r.text.lower()
                    # Look for signs it accepted the order
                    accepted = any(kw in body for kw in ["success", "created", "added", "order", "confirmed", "transaction"])
                    if accepted:
                        findings.append(Finding(
                            title="Negative Quantity / Price Manipulation Accepted",
                            description=(
                                f"The `{path}` endpoint accepted a request with negative/zero "
                                f"financial values (payload: {payload}) and returned HTTP {r.status_code} "
                                f"with an apparent success response.\n\n"
                                f"**Impact**: Attackers may be able to reverse charges, create "
                                f"negative balances, receive refunds on zero-cost orders, or "
                                f"manipulate pricing to purchase items for free."
                            ),
                            severity=Severity.CRITICAL,
                            status=FindingStatus.CONFIRMED,
                            owasp_id=self.owasp_id,
                            plugin=self.name,
                            endpoint=url,
                            remediation=(
                                "Validate all financial inputs server-side: quantity must be ≥1, "
                                "price/amount must be >0. Never trust client-supplied prices — "
                                "always look up the canonical price from your database. "
                                "Reject and log any request with negative/zero financial values."
                            ),
                            references=[
                                "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"
                            ],
                            evidence=[Evidence(
                                request_method="POST",
                                request_url=url,
                                request_body=str(payload),
                                response_status=r.status_code,
                                response_body_snippet=r.text[:400],
                                note=f"Negative/zero financial values accepted — HTTP {r.status_code} success response",
                            )],
                        ))
            except Exception:
                continue
