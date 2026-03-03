"""
Plugin: CORS Misconfiguration

Tests for dangerous Cross-Origin Resource Sharing configurations that
allow untrusted origins to read API responses, steal tokens, or make
authenticated requests on behalf of other users.

OWASP API Top 10: API8:2023 — Security Misconfiguration
"""

from __future__ import annotations

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient

# Test origins we'll probe with
EVIL_ORIGIN = "https://evil-attacker.com"
NULL_ORIGIN = "null"


class CORSPlugin(BasePlugin):
    name = "cors"
    description = "CORS misconfiguration detection"
    owasp_id = "API8:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []

        # ── Test 1: Arbitrary origin reflection ──────────────────────────
        try:
            resp = await client.get("/", headers={"Origin": EVIL_ORIGIN})
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()

            if acao == EVIL_ORIGIN:
                # Reflected arbitrary origin
                if acac == "true":
                    # Critical: reflects origin AND allows credentials
                    findings.append(Finding(
                        title="CORS: Arbitrary Origin Reflected with Credentials Allowed",
                        description=(
                            "The API reflects any arbitrary Origin header back in "
                            "Access-Control-Allow-Origin AND sets "
                            "Access-Control-Allow-Credentials: true. "
                            "This is a critical CORS misconfiguration. An attacker can "
                            "host a malicious page that makes authenticated cross-origin "
                            "requests to this API and read the full response — including "
                            "session tokens, user data, or any sensitive API response."
                        ),
                        severity=Severity.CRITICAL,
                        status=FindingStatus.CONFIRMED,
                        owasp_id=self.owasp_id,
                        plugin=self.name,
                        endpoint=str(resp.url),
                        remediation=(
                            "Maintain an explicit allowlist of trusted origins. "
                            "Never reflect arbitrary origins when credentials are enabled. "
                            "Example: Access-Control-Allow-Origin: https://app.yourdomain.com"
                        ),
                        references=[
                            "https://portswigger.net/web-security/cors",
                            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                        ],
                        evidence=[Evidence.from_httpx(
                            resp.request, resp,
                            note=(
                                f"Sent Origin: {EVIL_ORIGIN} → "
                                f"Got ACAO: {acao}, ACAC: {acac}. "
                                "Full authenticated cross-origin read is possible."
                            ),
                        )],
                    ))
                else:
                    # Reflected but no credentials — lower severity
                    findings.append(Finding(
                        title="CORS: Arbitrary Origin Reflected (No Credentials)",
                        description=(
                            "The API reflects any arbitrary Origin in "
                            "Access-Control-Allow-Origin without requiring credentials. "
                            "Unauthenticated cross-origin reads are possible. If any "
                            "endpoint returns sensitive data without auth, it is exposed."
                        ),
                        severity=Severity.MEDIUM,
                        status=FindingStatus.CONFIRMED,
                        owasp_id=self.owasp_id,
                        plugin=self.name,
                        endpoint=str(resp.url),
                        remediation=(
                            "Define an explicit allowlist of trusted origins instead "
                            "of reflecting arbitrary values."
                        ),
                        references=["https://portswigger.net/web-security/cors"],
                        evidence=[Evidence.from_httpx(
                            resp.request, resp,
                            note=f"Sent Origin: {EVIL_ORIGIN} → Got ACAO: {acao}",
                        )],
                    ))

            elif acao == "*" and acac == "true":
                # Wildcard + credentials — browser rejects this but worth flagging
                findings.append(Finding(
                    title="CORS: Wildcard Origin with Credentials Flag",
                    description=(
                        "Access-Control-Allow-Origin: * is set alongside "
                        "Access-Control-Allow-Credentials: true. Browsers block this "
                        "combination, but it indicates a misconfigured CORS policy "
                        "that may be exploitable in non-browser clients or future "
                        "browser behavior changes."
                    ),
                    severity=Severity.MEDIUM,
                    status=FindingStatus.CONFIRMED,
                    owasp_id=self.owasp_id,
                    plugin=self.name,
                    endpoint=str(resp.url),
                    remediation=(
                        "Remove the wildcard and use an explicit origin allowlist. "
                        "Never combine ACAO: * with ACAC: true."
                    ),
                    evidence=[Evidence.from_httpx(
                        resp.request, resp,
                        note=f"ACAO: {acao}, ACAC: {acac}",
                    )],
                ))

        except httpx.HTTPError:
            pass

        # ── Test 2: Null origin ───────────────────────────────────────────
        try:
            resp_null = await client.get("/", headers={"Origin": NULL_ORIGIN})
            acao_null = resp_null.headers.get("access-control-allow-origin", "")
            acac_null = resp_null.headers.get("access-control-allow-credentials", "").lower()

            if acao_null == "null":
                findings.append(Finding(
                    title="CORS: Null Origin Accepted",
                    description=(
                        "The API accepts Origin: null and responds with "
                        "Access-Control-Allow-Origin: null. "
                        "The null origin is sent by sandboxed iframes, local files, "
                        "and data: URIs. An attacker can use a sandboxed iframe to "
                        "make cross-origin requests that appear to come from 'null' "
                        "and read the API response."
                        + (" Credentials are also allowed — this is exploitable." if acac_null == "true" else "")
                    ),
                    severity=Severity.HIGH if acac_null == "true" else Severity.MEDIUM,
                    status=FindingStatus.CONFIRMED,
                    owasp_id=self.owasp_id,
                    plugin=self.name,
                    endpoint=str(resp_null.url),
                    remediation=(
                        "Never allow the null origin in CORS policy. "
                        "Remove 'null' from your origin allowlist."
                    ),
                    references=["https://portswigger.net/web-security/cors#cors-vulnerability-with-null-origin"],
                    evidence=[Evidence.from_httpx(
                        resp_null.request, resp_null,
                        note=f"Sent Origin: null → Got ACAO: {acao_null}, ACAC: {acac_null}",
                    )],
                ))
        except httpx.HTTPError:
            pass

        # ── Test 3: Subdomain trust (prefix bypass) ───────────────────────
        # e.g. if target is api.example.com, test notexample.com
        host = target.host
        parts = host.split(".")
        if len(parts) >= 2:
            fake_subdomain = f"https://attacker-{'.'.join(parts[-2:])}"
            try:
                resp_sub = await client.get("/", headers={"Origin": fake_subdomain})
                acao_sub = resp_sub.headers.get("access-control-allow-origin", "")
                if acao_sub == fake_subdomain:
                    findings.append(Finding(
                        title="CORS: Prefix/Subdomain Origin Bypass",
                        description=(
                            f"The API accepted a forged subdomain origin ({fake_subdomain}). "
                            "The server appears to do a suffix match on the origin "
                            "rather than an exact match, allowing any domain that ends "
                            "with the target domain suffix to be trusted."
                        ),
                        severity=Severity.HIGH,
                        status=FindingStatus.CONFIRMED,
                        owasp_id=self.owasp_id,
                        plugin=self.name,
                        endpoint=str(resp_sub.url),
                        remediation=(
                            "Use exact string matching against an explicit origin allowlist. "
                            "Never use endsWith() or suffix matching for origin validation."
                        ),
                        evidence=[Evidence.from_httpx(
                            resp_sub.request, resp_sub,
                            note=f"Sent Origin: {fake_subdomain} → Got ACAO: {acao_sub}",
                        )],
                    ))
            except httpx.HTTPError:
                pass

        return findings
