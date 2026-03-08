"""
Plugin: Mass Assignment — Broken Object Property Level Authorization

OWASP API6:2023 — Mass Assignment / Auto-Binding

Occurs when an API automatically binds client-provided JSON/form fields
to internal model properties, allowing attackers to set fields they
should not be able to modify (e.g., role, plan, isAdmin, balance).

Detection strategy:
──────────────────────────────────────────────────────────────────────────────
1. REFLECTION TEST: POST/PUT with extra privilege fields — check if they
   appear in the response body (confirms server accepted and stored them)

2. FIELD LEAK via 422 ERRORS: Some frameworks validate inputs and list all
   accepted fields in 422 Unprocessable Entity errors — reveals the full
   server-side schema including internal fields

3. PLAN/ROLE ESCALATION: Attempt to modify plan/role/subscription fields
   that should be server-controlled — check if the change persists in a
   follow-up GET request

4. CREDENTIAL FIELDS: Attempt to set password_hash, api_key, oauth_token
   via a PUT update endpoint — check if the server reflects or accepts these
──────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import re
from typing import Optional
import json

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient


# Fields that should never be user-settable
PRIVILEGE_FIELDS = [
    # Role / admin escalation
    "role", "roles", "admin", "isAdmin", "is_admin", "superuser",
    "is_superuser", "staff", "is_staff", "moderator", "is_moderator",
    "privilege", "privileges", "permission", "permissions",
    # Plan / billing escalation
    "plan", "subscription", "tier", "level", "account_type",
    "premium", "is_premium", "pro", "is_pro", "enterprise",
    # Sensitive credential fields
    "password_hash", "hashed_password", "password_digest",
    "api_key", "access_token", "refresh_token", "oauth_token",
    "secret", "private_key",
    # Balance / financial
    "balance", "credit", "credits", "account_balance", "wallet",
    # Verification bypasses
    "email_verified", "is_verified", "verified", "active", "is_active",
    "banned", "is_banned", "blocked", "is_blocked",
    # Internal metadata
    "created_by", "updated_by", "owner_id", "user_id",
]

# Escalation probes — specific high-value field/value combinations
ESCALATION_PROBES = [
    {"role": "admin"},
    {"role": "ADMIN"},
    {"isAdmin": True},
    {"is_admin": True},
    {"admin": True},
    {"plan": "enterprise"},
    {"plan": "pro"},
    {"subscription": "premium"},
    {"tier": "admin"},
    {"privilege": "admin"},
    {"email_verified": True},
    {"active": True},
    {"balance": 99999},
]

# Endpoints to probe
MUTATION_PATHS = [
    "/api/v1/users/me",
    "/api/v2/users/me",
    "/api/users/me",
    "/api/v1/profile",
    "/api/profile",
    "/profile",
    "/api/v1/account",
    "/api/account",
    "/account",
    "/api/v1/settings",
    "/api/settings",
    "/settings",
    "/api/v1/user",
    "/api/user",
    "/user",
    "/api/v1/me",
    "/api/me",
    "/me",
]

REGISTRATION_PATHS = [
    "/api/v1/auth/register",
    "/api/auth/register",
    "/api/v1/register",
    "/api/register",
    "/register",
    "/api/v1/signup",
    "/api/signup",
    "/signup",
    "/api/v1/users",
    "/api/users",
    "/users",
]


class MassAssignmentPlugin(BasePlugin):
    name = "mass_assignment"
    description = "Mass assignment / broken object property level authorization (OWASP API6)"
    owasp_id = "API6:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []

        # ── 1. Field Leak via Validation Errors ───────────────────────────────
        leak_finding = await _test_field_leak(client)
        if leak_finding:
            findings.append(leak_finding)

        # ── 2. Reflection Test on Update Endpoints ────────────────────────────
        reflect_findings = await _test_reflection(client)
        findings.extend(reflect_findings)

        # ── 3. Registration Escalation ────────────────────────────────────────
        reg_finding = await _test_registration_escalation(client)
        if reg_finding:
            findings.append(reg_finding)

        return findings


async def _test_field_leak(client: SecForgeClient) -> Optional[Finding]:
    """
    Send an invalid request to trigger 422 validation errors.
    Some frameworks (FastAPI, Rails, NestJS) list all accepted fields
    in error responses — revealing internal model fields.
    """
    leak_paths = MUTATION_PATHS[:5] + REGISTRATION_PATHS[:3]
    found_internal_fields: list[tuple[str, list[str], Evidence]] = []

    for path in leak_paths:
        for method in ("POST", "PUT", "PATCH"):
            try:
                # Send a request with only a clearly invalid field
                resp = await client.request(
                    method, path,
                    json={"__probe__": "secforge_field_discovery"},
                )
                if resp.status_code in (400, 422, 200):
                    body = resp.text or ""
                    # Look for field names in the error response
                    found = _extract_field_names(body)
                    internal = [f for f in found if f.lower() in
                                [p.lower() for p in PRIVILEGE_FIELDS]]
                    if internal:
                        ev = Evidence.from_httpx(
                            resp.request, resp,
                            note=(
                                f"Validation error revealed internal field names: {internal}\n"
                                "These fields should not be user-settable."
                            ),
                        )
                        found_internal_fields.append((path, internal, ev))
            except httpx.HTTPError:
                continue

    if not found_internal_fields:
        return None

    all_fields = sorted({f for _, fields, _ in found_internal_fields for f in fields})
    all_evidence = [ev for _, _, ev in found_internal_fields[:4]]
    all_paths = [p for p, _, _ in found_internal_fields]

    return Finding(
        title="Mass Assignment: Internal Fields Exposed in Validation Errors",
        description=(
            "API validation error responses reveal the names of internal model fields "
            "that should not be client-settable. An attacker can use these field names "
            "to attempt privilege escalation via mass assignment.\n\n"
            f"Leaked privilege fields: {', '.join(all_fields)}\n\n"
            f"Affected endpoints:\n" + "\n".join(f"  • {p}" for p in all_paths)
        ),
        severity=Severity.MEDIUM,
        status=FindingStatus.CONFIRMED,
        owasp_id="API6:2023",
        plugin="mass_assignment",
        endpoint=found_internal_fields[0][0],
        remediation=(
            "Use explicit field allowlists (DTOs / request schemas) and never expose "
            "internal model field names in error messages. In FastAPI, define separate "
            "request and response schemas. In Rails, use strong parameters. "
            "Return generic error messages for invalid fields."
        ),
        references=[
            "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
        ],
        evidence=all_evidence,
    )


async def _test_reflection(client: SecForgeClient) -> list[Finding]:
    """
    POST/PUT privilege fields to update endpoints.
    Flag if: (a) server returns 200 and echoes the field back, or
             (b) a follow-up GET shows the field was persisted.
    """
    findings: list[Finding] = []
    confirmed: list[tuple[str, dict, Evidence, Optional[Evidence]]] = []

    for path in MUTATION_PATHS:
        # First check if the endpoint exists at all
        try:
            probe = await client.get(path)
            if probe.status_code == 404:
                continue
        except httpx.HTTPError:
            continue

        for escalation in ESCALATION_PROBES:
            for method in ("PUT", "PATCH"):
                try:
                    resp = await client.request(method, path, json=escalation)
                    if resp.status_code not in (200, 201, 202, 204):
                        continue

                    body = resp.text or ""
                    field_name = list(escalation.keys())[0]
                    field_value = list(escalation.values())[0]

                    # Check if the field value is reflected in the response
                    value_str = str(field_value).lower()
                    reflected = (
                        value_str in body.lower()
                        and field_name.lower() in body.lower()
                    )

                    if reflected:
                        ev_write = Evidence.from_httpx(
                            resp.request, resp,
                            note=f"Server accepted and reflected: {escalation}",
                        )

                        # Follow-up GET to check if it persisted
                        ev_read = None
                        try:
                            get_resp = await client.get(path)
                            if get_resp.status_code == 200:
                                get_body = get_resp.text or ""
                                if value_str in get_body.lower():
                                    ev_read = Evidence.from_httpx(
                                        get_resp.request, get_resp,
                                        note="Follow-up GET confirms field persisted after write",
                                    )
                        except httpx.HTTPError:
                            pass

                        confirmed.append((path, escalation, ev_write, ev_read))
                        break  # One confirmed payload per endpoint is enough

                except httpx.HTTPError:
                    continue

    if confirmed:
        for path, probe, ev_write, ev_read in confirmed[:3]:
            field = list(probe.keys())[0]
            value = list(probe.values())[0]
            persisted = ev_read is not None
            evidence = [ev_write] + ([ev_read] if ev_read else [])

            findings.append(Finding(
                title=f"Mass Assignment: Privilege Field '{field}' Accepted ({"Persisted" if persisted else "Reflected"})",
                description=(
                    f"The endpoint {path} accepted the privilege field '{field}={value}' "
                    f"in a {list(probe.keys())[0]} request and "
                    + ("persisted it (confirmed by follow-up GET)." if persisted
                       else "reflected it in the response body.")
                    + "\n\nAn attacker can escalate their account privileges by including "
                    "this field in any profile update request."
                ),
                severity=Severity.CRITICAL if field in ("role", "admin", "isAdmin", "is_admin",
                                                          "plan", "privilege") else Severity.HIGH,
                status=FindingStatus.CONFIRMED if persisted else FindingStatus.PROBABLE,
                owasp_id="API6:2023",
                plugin="mass_assignment",
                endpoint=path,
                remediation=(
                    f"Remove '{field}' from the allowed fields in the update endpoint's "
                    "request schema. Use a DTO/allowlist pattern: only accept fields "
                    "explicitly permitted for user modification. "
                    f"The '{field}' field must only be settable by internal server logic "
                    "or admin endpoints with elevated authorization."
                ),
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
                ],
                evidence=evidence,
            ))

    return findings


async def _test_registration_escalation(
    client: SecForgeClient,
) -> Optional[Finding]:
    """
    Attempt to register a new account with elevated privilege fields.
    Uses a unique test email to avoid conflicts.
    """
    import random, string
    rand_suffix = "".join(random.choices(string.ascii_lowercase, k=8))
    test_email = f"secforge_probe_{rand_suffix}@probe.internal"

    base_payload = {
        "email": test_email,
        "password": "ApiScanProbe2026!",
        "username": f"secforge_{rand_suffix}",
        "name": "ApiScan Probe",
    }

    for path in REGISTRATION_PATHS:
        for escalation in [{"role": "admin"}, {"isAdmin": True}, {"plan": "enterprise"}]:
            try:
                payload = {**base_payload, **escalation}
                resp = await client.request("POST", path, json=payload)

                if resp.status_code in (200, 201):
                    body = resp.text or ""
                    field = list(escalation.keys())[0]
                    value = str(list(escalation.values())[0]).lower()

                    # Check if the elevated value appears in the registration response
                    if value in body.lower() or field.lower() in body.lower():
                        ev = Evidence.from_httpx(
                            resp.request, resp,
                            note=f"Registration accepted privilege field: {escalation}",
                        )
                        return Finding(
                            title=f"Mass Assignment: Account Registered with Elevated '{field}' Field",
                            description=(
                                f"The registration endpoint {path} accepted '{field}={list(escalation.values())[0]}' "
                                "as part of the registration payload and returned it in the response.\n\n"
                                "An attacker can self-register admin/premium accounts by adding "
                                "privilege fields to the registration request.\n\n"
                                f"Registration payload sent: {json.dumps(payload, indent=2)}"
                            ),
                            severity=Severity.CRITICAL,
                            status=FindingStatus.PROBABLE,  # Can't confirm persistence without login
                            owasp_id="API6:2023",
                            plugin="mass_assignment",
                            endpoint=path,
                            remediation=(
                                "Use a strict input schema for registration that only accepts "
                                "explicitly permitted fields (email, password, name). "
                                "Reject all other fields with a 400 error. "
                                "Never pass the raw registration request object to your ORM."
                            ),
                            references=[
                                "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
                            ],
                            evidence=[ev],
                        )
            except httpx.HTTPError:
                continue

    return None


def _extract_field_names(body: str) -> list[str]:
    """Extract field names from validation error messages."""
    found = []
    # FastAPI / Pydantic style: {"detail": [{"loc": ["body", "fieldname"], ...}]}
    loc_matches = re.findall(r'"loc":\s*\[[^\]]*"([a-zA-Z_][a-zA-Z0-9_]*)"\s*\]', body)
    found.extend(loc_matches)
    # Rails style: {"errors": {"fieldname": [...]}}
    error_keys = re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]*)":\s*\[', body)
    found.extend(error_keys)
    # Generic: "field 'fieldname' is required"
    field_mentions = re.findall(r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\'].*(?:required|invalid|missing)', body, re.IGNORECASE)
    found.extend(field_mentions)
    return list(set(found))
