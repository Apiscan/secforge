"""
Plugin: JWT Security Assessment

Advanced JWT attack coverage beyond the basic alg:none check in auth.py:

1. Algorithm Confusion (RS256 → HS256)
   If the server uses RS256 (asymmetric), an attacker can try signing a token
   with the server's PUBLIC key treated as an HMAC secret. Many libraries that
   don't explicitly whitelist algorithms will accept it.

2. Weak Secret Brute-Force (HS256/HS384/HS512)
   Try common secrets against the current token signature.
   If we can verify the signature = we can forge new tokens.

3. kid (Key ID) Injection
   Manipulate the `kid` header to point to:
   - /dev/null (empty key → empty HMAC)
   - SQL injection payloads
   - Path traversal

4. JWT Expiry / Claims Inspection
   Flag tokens with no expiry (exp), overly long TTL (>24h), or
   dangerous claims (is_admin: false → try setting true).

OWASP API Top 10: API2:2023 — Broken Authentication
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Optional

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient

# Common weak HMAC secrets to try
WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin", "key",
    "jwt_secret", "mysecret", "changeme", "supersecret", "letmein",
    "token_secret", "api_secret", "app_secret", "your-256-bit-secret",
    "your-secret-key", "", "null", "undefined", "test", "dev",
]

# Test endpoints to probe with forged tokens
PROBE_PATHS = [
    "/api/v1/users/me", "/api/v1/profile", "/api/v1/me",
    "/me", "/profile", "/api/v1/users/1",
]


class JWTPlugin(BasePlugin):
    name = "jwt"
    description = "Advanced JWT security: algorithm confusion, weak secrets, kid injection"
    owasp_id = "API2:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []

        if target.auth.type != "bearer" or not target.auth.token:
            return []

        token = target.auth.token.strip()
        parts = token.split(".")
        if len(parts) != 3:
            return []

        header, payload = _decode_part(parts[0]), _decode_part(parts[1])
        if not header or not payload:
            return []

        alg = header.get("alg", "").upper()

        # ── 1. Claims inspection ──────────────────────────────────────────
        findings.extend(_inspect_claims(payload, token, target))

        # ── 2. Weak secret brute-force (HS* algorithms) ───────────────────
        if alg.startswith("HS"):
            secret = _brute_force_secret(parts, alg)
            if secret is not None:
                forged = _forge_token(header, payload, secret, alg)
                ev = Evidence.observed(
                    note=(
                        f"JWT secret brute-forced: secret={secret!r}. "
                        f"Algorithm: {alg}. Any token can now be forged."
                    ),
                    url=target.url,
                )
                findings.append(Finding(
                    title=f"JWT Weak Secret Discovered: {alg} signed with {secret!r}",
                    description=(
                        f"The JWT is signed with a weak, guessable secret ({secret!r}) "
                        f"using {alg}. Anyone who discovers this secret can forge tokens "
                        "for any user or privilege level — including admin accounts."
                    ),
                    severity=Severity.CRITICAL,
                    status=FindingStatus.CONFIRMED,
                    owasp_id=self.owasp_id,
                    plugin=self.name,
                    endpoint=target.url,
                    remediation=(
                        "Use a cryptographically random secret of at least 256 bits. "
                        "Rotate the secret immediately. Consider switching to RS256 "
                        "(asymmetric) for additional security — private key stays server-side."
                    ),
                    references=[
                        "https://portswigger.net/web-security/jwt",
                        "https://auth0.com/blog/brute-forcing-hs256-is-possible/",
                    ],
                    evidence=[ev],
                ))

        # ── 3. Algorithm confusion RS256 → HS256 ─────────────────────────
        if alg == "RS256":
            confusion_findings = await _test_alg_confusion(
                client, target, header, payload, parts[2]
            )
            findings.extend(confusion_findings)

        # ── 4. kid injection ─────────────────────────────────────────────
        kid_findings = await _test_kid_injection(client, target, header, payload)
        findings.extend(kid_findings)

        return findings


# ────────────────────────────────────────────────────────────────────────────
# Claims inspection
# ────────────────────────────────────────────────────────────────────────────

def _inspect_claims(payload: dict, token: str, target: TargetConfig) -> list[Finding]:
    findings = []
    now = int(time.time())

    exp = payload.get("exp")
    iat = payload.get("iat")

    # No expiry
    if exp is None:
        findings.append(Finding(
            title="JWT Has No Expiry (exp claim missing)",
            description=(
                "The JWT token has no expiration claim (exp). "
                "A stolen token remains valid forever — there is no way to "
                "invalidate it without rotating the signing secret."
            ),
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            owasp_id="API2:2023",
            plugin="jwt",
            endpoint=target.url,
            remediation="Always set a short exp claim (15 min for access tokens, 7 days for refresh tokens).",
            evidence=[Evidence.observed(
                note=f"Decoded JWT payload: {json.dumps(payload)[:500]}. No 'exp' field found.",
                url=target.url,
            )],
        ))
    else:
        # Long TTL (> 24 hours)
        remaining = exp - now
        if remaining > 0 and remaining > 86400:
            hours = remaining // 3600
            findings.append(Finding(
                title=f"JWT Long Expiry: {hours}h remaining",
                description=(
                    f"The JWT expires in {hours} hours. Long-lived tokens increase "
                    "the window of opportunity for a stolen token to be abused. "
                    "Best practice is ≤1 hour for access tokens."
                ),
                severity=Severity.LOW,
                status=FindingStatus.CONFIRMED,
                owasp_id="API2:2023",
                plugin="jwt",
                endpoint=target.url,
                remediation="Shorten token lifetime to ≤1h. Use refresh tokens for long-lived sessions.",
                evidence=[Evidence.observed(
                    note=f"exp={exp}, iat={iat}, remaining={remaining}s ({hours}h)",
                    url=target.url,
                )],
            ))

    # Sensitive privilege claims that could be manipulated
    dangerous_claims = {k: v for k, v in payload.items()
                        if any(x in k.lower() for x in ["admin", "role", "scope", "perm", "priv", "super"])}
    if dangerous_claims:
        findings.append(Finding(
            title="JWT Contains Privilege Claims (Attack Surface)",
            description=(
                "The JWT payload contains privilege-related claims: "
                + ", ".join(f"{k}={v!r}" for k, v in dangerous_claims.items())
                + ". If the signing algorithm or secret is weak, an attacker "
                "can modify these claims to escalate privileges."
            ),
            severity=Severity.INFO,
            status=FindingStatus.CONFIRMED,
            owasp_id="API2:2023",
            plugin="jwt",
            endpoint=target.url,
            remediation=(
                "Privilege decisions should be made server-side from the database, "
                "not from JWT claims alone. Use JWT claims only as hints, always verify "
                "the actual permission in the backend."
            ),
            evidence=[Evidence.observed(
                note=f"Privilege claims in JWT: {dangerous_claims}",
                url=target.url,
            )],
        ))

    return findings


# ────────────────────────────────────────────────────────────────────────────
# Weak secret brute-force
# ────────────────────────────────────────────────────────────────────────────

def _brute_force_secret(parts: list[str], alg: str) -> Optional[str]:
    """Try WEAK_SECRETS against the token. Return matching secret or None."""
    digest_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    digest_fn = digest_map.get(alg, hashlib.sha256)

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        expected_sig = base64.urlsafe_b64decode(parts[2] + "==")
    except Exception:
        return None

    for secret in WEAK_SECRETS:
        sig = hmac.new(secret.encode(), signing_input, digest_fn).digest()
        if hmac.compare_digest(sig, expected_sig):
            return secret
    return None


def _forge_token(header: dict, payload: dict, secret: str, alg: str) -> str:
    """Forge a new JWT with the discovered secret."""
    digest_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    digest_fn = digest_map.get(alg, hashlib.sha256)

    h = _b64_encode(json.dumps(header, separators=(",", ":")))
    p = _b64_encode(json.dumps(payload, separators=(",", ":")))
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, digest_fn).digest()
    return f"{h}.{p}.{_b64_encode_bytes(sig)}"


# ────────────────────────────────────────────────────────────────────────────
# Algorithm confusion RS256 → HS256
# ────────────────────────────────────────────────────────────────────────────

async def _test_alg_confusion(
    client: SecForgeClient,
    target: TargetConfig,
    header: dict,
    payload: dict,
    original_sig: str,
) -> list[Finding]:
    """
    The RS256→HS256 attack:
    Some JWT libraries, when told alg=HS256, use the configured 'public key'
    as the HMAC secret. If we can get the server's public key (from JWKS),
    we can forge tokens signed with it.
    """
    findings = []

    # Try to fetch the public key from common JWKS endpoints
    jwks_paths = ["/.well-known/jwks.json", "/api/v1/.well-known/jwks.json",
                  "/oauth/jwks", "/auth/jwks", "/.well-known/openid-configuration"]

    public_key_pem = None
    for path in jwks_paths:
        try:
            resp = await client.get(path)
            if resp.status_code == 200:
                data = resp.json()
                # Flag JWKS endpoint exposed (info)
                findings.append(Finding(
                    title="JWKS Public Key Endpoint Exposed",
                    description=(
                        f"Public key endpoint discovered at {path}. "
                        "While JWKS is standard, its presence confirms RS256 usage "
                        "and enables algorithm confusion attacks if the JWT library "
                        "does not whitelist accepted algorithms."
                    ),
                    severity=Severity.INFO,
                    status=FindingStatus.CONFIRMED,
                    owasp_id="API2:2023",
                    plugin="jwt",
                    endpoint=str(resp.url),
                    remediation=(
                        "Explicitly whitelist 'RS256' in your JWT library config. "
                        "Never allow the client to specify the algorithm."
                    ),
                    evidence=[Evidence.from_httpx(resp.request, resp,
                        note=f"JWKS endpoint at {path} returned HTTP 200")],
                ))
                break
        except (httpx.HTTPError, ValueError):
            continue

    # Build confusion token: alg=HS256, signed with "public_key" as secret
    # Even without the real key, flag the attack surface if RS256 is in use
    confusion_header = {**header, "alg": "HS256"}
    confusion_payload = {**payload}

    # Try empty string and null as HS256 secrets (degenerate confusion)
    for dummy_secret in ["", "null", "public_key"]:
        forged = _forge_token(confusion_header, confusion_payload, dummy_secret, "HS256")
        for path in PROBE_PATHS:
            try:
                resp = await client.get(path, headers={"Authorization": f"Bearer {forged}"})
                if resp.status_code == 200:
                    body = resp.text[:200]
                    findings.append(Finding(
                        title="JWT Algorithm Confusion: RS256 → HS256 Accepted",
                        description=(
                            "The server accepted a JWT forged with alg=HS256 using a "
                            f"trivial secret ({dummy_secret!r}). This is the algorithm "
                            "confusion attack: the server was configured for RS256 but "
                            "accepted an HMAC-signed token. An attacker can forge arbitrary "
                            "tokens without knowing the private key."
                        ),
                        severity=Severity.CRITICAL,
                        status=FindingStatus.CONFIRMED,
                        owasp_id="API2:2023",
                        plugin="jwt",
                        endpoint=path,
                        remediation=(
                            "Explicitly whitelist the expected algorithm in your JWT library. "
                            "Never allow algorithm negotiation from the token header."
                        ),
                        references=["https://portswigger.net/web-security/jwt/algorithm-confusion"],
                        evidence=[Evidence.from_httpx(resp.request, resp,
                            note=f"Forged HS256 token accepted at {path}, secret={dummy_secret!r}")],
                    ))
                    return findings
            except httpx.HTTPError:
                continue

    return findings


# ────────────────────────────────────────────────────────────────────────────
# kid injection
# ────────────────────────────────────────────────────────────────────────────

async def _test_kid_injection(
    client: SecForgeClient,
    target: TargetConfig,
    header: dict,
    payload: dict,
) -> list[Finding]:
    """Test kid header injection: /dev/null path, SQL injection."""
    findings = []

    kid_payloads = {
        "/dev/null": "",        # Empty file = empty HMAC key
        "../../dev/null": "",
        "' OR 1=1--": "",       # SQLi in kid
        "../../../../../dev/null": "",
    }

    for kid_val, secret in kid_payloads.items():
        attack_header = {**header, "kid": kid_val}
        # Remove alg confusion — keep original or force HS256
        attack_header["alg"] = "HS256"
        forged = _forge_token(attack_header, payload, secret, "HS256")

        for path in PROBE_PATHS[:2]:  # Limit probes
            try:
                resp = await client.get(path, headers={"Authorization": f"Bearer {forged}"})
                if resp.status_code == 200 and len(resp.text) > 20:
                    findings.append(Finding(
                        title=f"JWT kid Injection: Forged Token Accepted (kid={kid_val!r})",
                        description=(
                            f"The server accepted a JWT with kid={kid_val!r}. "
                            "The kid header was manipulated to point to a predictable or "
                            "empty key source, allowing token forgery without knowing the "
                            "legitimate signing key."
                        ),
                        severity=Severity.CRITICAL,
                        status=FindingStatus.CONFIRMED,
                        owasp_id="API2:2023",
                        plugin="jwt",
                        endpoint=path,
                        remediation=(
                            "Validate the kid header against a strict allowlist of known key IDs. "
                            "Never use the kid value to construct file paths or database queries."
                        ),
                        references=["https://portswigger.net/web-security/jwt#injecting-self-signed-jwts-via-the-kid-parameter"],
                        evidence=[Evidence.from_httpx(resp.request, resp,
                            note=f"kid={kid_val!r} accepted, empty HMAC secret worked at {path}")],
                    ))
                    return findings  # One confirmed is enough
            except httpx.HTTPError:
                continue

    return findings


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

def _decode_part(part: str) -> Optional[dict]:
    try:
        padded = part + "=" * (4 - len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode())
    except Exception:
        return None


def _b64_encode(data: str) -> str:
    return base64.urlsafe_b64encode(data.encode()).rstrip(b"=").decode()


def _b64_encode_bytes(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
