"""
Plugin: TLS/SSL Assessment

Checks TLS configuration for common weaknesses:
- Protocol version (TLS 1.0/1.1 deprecated, TLS 1.2+ required)
- Certificate validity and expiry
- Self-signed certificate detection
- Certificate hostname mismatch

OWASP API Top 10: API8:2023 — Security Misconfiguration
"""

from __future__ import annotations

import ssl
import socket
import datetime
from urllib.parse import urlparse

import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient


class TLSPlugin(BasePlugin):
    name = "tls"
    description = "TLS/SSL certificate and protocol assessment"
    owasp_id = "API8:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []

        if not target.is_https:
            findings.append(Finding(
                title="Plaintext HTTP — No Encryption",
                description=(
                    "The target is using HTTP (plaintext), not HTTPS. "
                    "All traffic — including authentication tokens, API keys, "
                    "and sensitive data — is transmitted without encryption "
                    "and is trivially interceptable via network sniffing."
                ),
                severity=Severity.CRITICAL,
                status=FindingStatus.CONFIRMED,
                owasp_id=self.owasp_id,
                plugin=self.name,
                endpoint=target.url,
                remediation=(
                    "Enforce HTTPS on all endpoints. Obtain a valid TLS certificate "
                    "(Let's Encrypt is free). Redirect all HTTP traffic to HTTPS."
                ),
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"
                ],
                evidence=[Evidence.observed(
                    note="Target URL uses HTTP scheme — no TLS in use",
                    url=target.url,
                    method="GET",
                )],
            ))
            return findings

        # Gather TLS info
        parsed = urlparse(target.url)
        host = parsed.hostname or parsed.netloc
        port = parsed.port or 443

        tls_info = await _get_tls_info(host, port)
        if tls_info.get("error"):
            findings.append(Finding(
                title="TLS Probe Failed",
                description=f"Could not establish TLS connection: {tls_info['error']}",
                severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED,
                plugin=self.name,
                endpoint=target.url,
                evidence=[Evidence.observed(
                    note=f"TLS connection error: {tls_info['error']}",
                    url=target.url,
                )],
            ))
            return findings

        proto = tls_info.get("protocol", "")
        cert = tls_info.get("cert", {})
        not_after_str = tls_info.get("not_after", "")
        is_self_signed = tls_info.get("self_signed", False)
        subject_cn = tls_info.get("subject_cn", "")

        # ── Check: Deprecated TLS version ────────────────────────────────
        deprecated = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}
        if proto in deprecated:
            findings.append(Finding(
                title=f"Deprecated TLS Version in Use: {proto}",
                description=(
                    f"The server supports {proto}, which is cryptographically weak "
                    "and officially deprecated by RFC 8996. Clients using this "
                    "version are vulnerable to POODLE, BEAST, and related attacks."
                ),
                severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED,
                owasp_id=self.owasp_id,
                plugin=self.name,
                endpoint=target.url,
                remediation="Disable TLS 1.0 and 1.1. Support TLS 1.2 and TLS 1.3 only.",
                references=[
                    "https://datatracker.ietf.org/doc/html/rfc8996",
                ],
                evidence=[Evidence.observed(
                    note=f"TLS handshake negotiated {proto} (deprecated)",
                    url=target.url,
                    response_headers={"TLS-Protocol": proto},
                )],
            ))

        # ── Check: Hostname mismatch ──────────────────────────────────────
        # Check both CN and Subject Alternative Names (SANs) — cert may be valid via SAN
        subject_cn = tls_info.get("subject_cn", "")
        san_names = tls_info.get("san_names", [])
        all_names = ([subject_cn] if subject_cn else []) + san_names
        host_covered = any(_cn_matches_host(name, host) for name in all_names)
        if subject_cn and not host_covered:
            findings.append(Finding(
                title="TLS Certificate Hostname Mismatch",
                description=(
                    f"The certificate Common Name (CN={subject_cn!r}) does not match "
                    f"the hostname/IP being connected to ({host!r}). "
                    "Clients validating certificates will reject this connection. "
                    "This indicates either a misconfigured certificate or a potential MITM."
                ),
                severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED,
                owasp_id=self.owasp_id,
                plugin=self.name,
                endpoint=target.url,
                remediation=(
                    f"Issue a certificate with CN or SAN matching {host!r}. "
                    "If using an IP, ensure the certificate has a Subject Alternative Name (SAN) for that IP."
                ),
                evidence=[Evidence.observed(
                    note=f"Certificate CN={subject_cn!r} does not match target host {host!r}",
                    url=target.url,
                )],
            ))

        # ── Check: Untrusted CA ───────────────────────────────────────────
        issuer_cn = tls_info.get("issuer_cn", "")
        untrusted = _probe_untrusted_ca(host, port)
        if untrusted:
            findings.append(Finding(
                title=f"Untrusted Certificate Authority: {issuer_cn or 'Unknown CA'}",
                description=(
                    f"The certificate is signed by {issuer_cn!r}, which is not in the "
                    "browser/system trust store. Clients will display security warnings "
                    "or reject the connection entirely. This is effectively equivalent "
                    "to a self-signed certificate from a trust perspective."
                ),
                severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED,
                owasp_id=self.owasp_id,
                plugin=self.name,
                endpoint=target.url,
                remediation=(
                    "Replace with a certificate from a trusted CA. "
                    "Let's Encrypt provides free, trusted certificates via certbot."
                ),
                references=["https://letsencrypt.org/getting-started/"],
                evidence=[Evidence.observed(
                    note=f"TLS connection with CERT_REQUIRED failed — CA {issuer_cn!r} not trusted",
                    url=target.url,
                )],
            ))

        # ── Check: TLS 1.2 only (no TLS 1.3) ────────────────────────────
        if proto == "TLSv1.2" and proto not in deprecated:
            findings.append(Finding(
                title="TLS 1.3 Not Supported",
                description=(
                    "The server is using TLS 1.2 but does not offer TLS 1.3. "
                    "TLS 1.3 provides significantly better performance and forward "
                    "secrecy than TLS 1.2."
                ),
                severity=Severity.LOW,
                status=FindingStatus.PROBABLE,
                owasp_id=self.owasp_id,
                plugin=self.name,
                endpoint=target.url,
                remediation="Enable TLS 1.3 alongside TLS 1.2 on your web server.",
                evidence=[Evidence.observed(
                    note=f"TLS handshake negotiated {proto} only",
                    url=target.url,
                )],
            ))

        # ── Check: Self-signed certificate ───────────────────────────────
        if is_self_signed:
            findings.append(Finding(
                title="Self-Signed TLS Certificate",
                description=(
                    "The server is presenting a self-signed certificate not issued "
                    "by a trusted Certificate Authority. Clients cannot verify the "
                    "server's identity, making the connection vulnerable to MITM attacks. "
                    "Automated scanners and browsers will reject or warn about this connection."
                ),
                severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED,
                owasp_id=self.owasp_id,
                plugin=self.name,
                endpoint=target.url,
                remediation=(
                    "Replace the self-signed certificate with one from a trusted CA. "
                    "Let's Encrypt provides free certificates via certbot."
                ),
                references=["https://letsencrypt.org/getting-started/"],
                evidence=[Evidence.observed(
                    note=f"Certificate subject CN={subject_cn!r} is self-signed (issuer = subject)",
                    url=target.url,
                )],
            ))

        # ── Check: Certificate expiry ─────────────────────────────────────
        if not_after_str:
            try:
                not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                days_remaining = (not_after - now).days

                if days_remaining < 0:
                    findings.append(Finding(
                        title="TLS Certificate Expired",
                        description=(
                            f"The TLS certificate expired {abs(days_remaining)} days ago "
                            f"(on {not_after_str}). Clients will reject this connection with "
                            "a security warning. Authentication tokens cannot be trusted."
                        ),
                        severity=Severity.CRITICAL,
                        status=FindingStatus.CONFIRMED,
                        plugin=self.name,
                        endpoint=target.url,
                        remediation="Renew the TLS certificate immediately.",
                        evidence=[Evidence.observed(
                            note=f"Certificate expired: {not_after_str}",
                            url=target.url,
                        )],
                    ))
                elif days_remaining < 14:
                    findings.append(Finding(
                        title=f"TLS Certificate Expiring Soon ({days_remaining} days)",
                        description=(
                            f"The TLS certificate expires in {days_remaining} days "
                            f"({not_after_str}). Failure to renew will cause all clients "
                            "to reject the connection."
                        ),
                        severity=Severity.HIGH,
                        status=FindingStatus.CONFIRMED,
                        plugin=self.name,
                        endpoint=target.url,
                        remediation="Renew the TLS certificate immediately.",
                        evidence=[Evidence.observed(
                            note=f"Certificate expiry: {not_after_str} ({days_remaining} days remaining)",
                            url=target.url,
                        )],
                    ))
                elif days_remaining < 30:
                    findings.append(Finding(
                        title=f"TLS Certificate Expiring Within 30 Days ({days_remaining} days)",
                        description=f"Certificate expires {not_after_str}.",
                        severity=Severity.MEDIUM,
                        status=FindingStatus.CONFIRMED,
                        plugin=self.name,
                        endpoint=target.url,
                        remediation="Schedule certificate renewal.",
                        evidence=[Evidence.observed(
                            note=f"Certificate expiry: {not_after_str}",
                            url=target.url,
                        )],
                    ))
            except Exception:
                pass  # Date parsing failed — skip expiry check

        return findings


async def _get_tls_info(host: str, port: int) -> dict:
    """Probe TLS info via ssl module. Returns dict with protocol, cert, flags."""
    import asyncio

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _probe_tls_sync, host, port)


def _probe_tls_sync(host: str, port: int) -> dict:
    """Synchronous TLS probe — runs in threadpool.
    
    Uses CERT_NONE to always successfully connect and retrieve cert info,
    even for self-signed or expired certificates — we report those as findings.
    """
    try:
        # Use CERT_NONE so we can always retrieve cert details regardless of validity.
        # We report self-signed / expired as findings ourselves.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                proto = ssock.version() or ""
                # getpeercert() with binary_form=False returns empty dict when CERT_NONE
                # Use binary_form=True + DER decode to get cert details
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert() or {}

                # Parse cert from binary form if needed
                if not cert and cert_bin:
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        c = x509.load_der_x509_certificate(cert_bin, default_backend())
                        subject_cn = _get_cn(c.subject)
                        issuer_cn = _get_cn(c.issuer)
                        not_after = c.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT")
                        is_self_signed = (c.subject == c.issuer)
                        san_names = _extract_sans_from_crypto(c)
                        return {
                            "protocol": proto,
                            "cert": cert,
                            "subject_cn": subject_cn,
                            "issuer_cn": issuer_cn,
                            "not_after": not_after,
                            "self_signed": is_self_signed,
                            "san_names": san_names,
                        }
                    except Exception:
                        pass

                subject_dict = dict(x[0] for x in cert.get("subject", []))
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                subject_cn = subject_dict.get("commonName", "")
                issuer_cn = issuer_dict.get("commonName", "")
                not_after = cert.get("notAfter", "")
                is_self_signed = (subject_dict == issuer_dict) if subject_dict else False

                # Extract SANs from the ssl module cert dict
                san_names = []
                for san_type, san_val in cert.get("subjectAltName", []):
                    if san_type.lower() == "dns":
                        san_names.append(san_val)

                return {
                    "protocol": proto,
                    "cert": cert,
                    "subject_cn": subject_cn,
                    "issuer_cn": issuer_cn,
                    "not_after": not_after,
                    "self_signed": is_self_signed,
                    "san_names": san_names,
                }
    except ssl.SSLError as e:
        return {"error": f"SSL error: {e}"}
    except OSError as e:
        return {"error": f"Connection error: {e}"}
    except Exception as e:
        return {"error": str(e)}


def _extract_sans_from_crypto(cert) -> list[str]:
    """Extract DNS SANs from a cryptography x509 certificate object."""
    try:
        from cryptography.x509 import SubjectAlternativeName, DNSName
        from cryptography.x509.oid import ExtensionOID
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return ext.value.get_values_for_type(DNSName)
    except Exception:
        return []


def _get_cn(name) -> str:
    """Extract CN from cryptography x509 Name object."""
    try:
        from cryptography.x509.oid import NameOID
        return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return str(name)


def _cn_matches_host(cn: str, host: str) -> bool:
    """Check if a certificate CN matches the target host (basic check)."""
    import fnmatch
    cn = cn.lower()
    host = host.lower()
    if cn == host:
        return True
    # Wildcard support: *.example.com matches api.example.com
    if cn.startswith("*."):
        return fnmatch.fnmatch(host, cn)
    return False


def _probe_untrusted_ca(host: str, port: int) -> bool:
    """Return True if the certificate fails system CA verification."""
    try:
        ctx = ssl.create_default_context()  # Uses system trust store, CERT_REQUIRED by default
        ctx.check_hostname = False
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as _:
                return False  # Verification passed — trusted CA
    except ssl.SSLCertVerificationError:
        return True   # Cert failed system CA verification
    except Exception:
        return False  # Other error — don't flag
