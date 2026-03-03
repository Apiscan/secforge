"""
Plugin: Security Misconfiguration

OWASP API8:2023 — Security Misconfiguration

Tests for common configuration mistakes that expose sensitive information
or functionality that should never be accessible in production.

Checks:
──────────────────────────────────────────────────────────────────────────────
1. DEBUG / ADMIN ENDPOINTS: Spring Actuator, Django debug toolbar, Flask debug
   mode endpoints, internal admin routes — often left exposed in production

2. SENSITIVE FILE EXPOSURE: .env, .git/config, backup files, configuration
   files — contain credentials, infrastructure details, source code

3. VERBOSE ERROR RESPONSES: Stack traces, internal paths, library versions,
   database queries in error responses — information disclosure

4. DEFAULT CREDENTIALS on well-known admin interfaces

5. DIRECTORY LISTING: Index pages with file listings

6. CORS Misconfiguration cross-check (complements cors plugin)

7. HTTP METHODS: TRACE/TRACK enabled (XST — cross-site tracing)
──────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import re
from typing import Optional
import httpx

from secforge.plugins.base import BasePlugin
from secforge.models.finding import Finding
from secforge.models.evidence import Evidence
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig
from secforge.core.client import SecForgeClient


# ── Spring Actuator Endpoints ─────────────────────────────────────────────────
ACTUATOR_ENDPOINTS = {
    "/actuator": "Actuator root — lists all exposed endpoints",
    "/actuator/health": "Health endpoint — may expose DB/service status",
    "/actuator/env": "CRITICAL: Environment variables including secrets",
    "/actuator/beans": "Spring bean definitions — reveals full application structure",
    "/actuator/mappings": "Request handler mappings — reveals all API routes",
    "/actuator/httptrace": "HTTP request/response history — may contain tokens",
    "/actuator/auditevents": "Security audit events — login failures, access denials",
    "/actuator/loggers": "Logger configuration — can be used to enable debug logging",
    "/actuator/metrics": "Application metrics",
    "/actuator/info": "Application info — version, git commit, build details",
    "/actuator/threaddump": "JVM thread dump",
    "/actuator/heapdump": "CRITICAL: Full JVM heap dump — contains all in-memory data",
    "/actuator/shutdown": "CRITICAL: Remotely shut down the application",
    "/actuator/restart": "Remotely restart the application",
}

# ── Debug / Internal Endpoints ────────────────────────────────────────────────
DEBUG_ENDPOINTS = {
    "/debug": "Generic debug endpoint",
    "/_debug": "Internal debug endpoint",
    "/api/debug": "API debug endpoint",
    "/__debug__": "Django Debug Toolbar",
    "/api/v1/debug": "Versioned debug endpoint",
    "/__admin__": "Django admin interface",
    "/admin": "Admin interface",
    "/admin/": "Admin interface",
    "/api/admin": "API admin endpoint",
    "/api/v1/admin": "Versioned API admin",
    "/management": "Management endpoint",
    "/management/health": "Management health",
    "/console": "Web console (H2, etc.)",
    "/h2-console": "H2 Database console — direct DB access",
    "/api-explorer": "Swagger UI / API explorer",
    "/swagger": "Swagger UI",
    "/swagger-ui": "Swagger UI",
    "/swagger-ui.html": "Swagger UI",
    "/swagger-ui/index.html": "Swagger UI",
    "/api/swagger-ui": "API Swagger UI",
    "/graphql": "GraphQL endpoint (handled by graphql plugin)",
    "/graphiql": "GraphiQL interface — interactive GraphQL explorer",
    "/playground": "GraphQL Playground",
    "/api/graphql": "API GraphQL endpoint",
    "/metrics": "Prometheus metrics — may expose internal counts",
    "/health": "Health check endpoint",
    "/healthz": "Health check (k8s)",
    "/readyz": "Readiness check (k8s)",
    "/livez": "Liveness check (k8s)",
    "/status": "Status endpoint",
    "/server-status": "Apache server status",
    "/server-info": "Apache server info",
    "/nginx_status": "nginx status",
    "/phpinfo.php": "PHP info page",
    "/info.php": "PHP info page",
    "/test.php": "PHP test page",
}

# ── Sensitive File Paths ──────────────────────────────────────────────────────
SENSITIVE_FILES = {
    "/.env": "Environment file — may contain database credentials, API keys",
    "/.env.local": "Local environment file",
    "/.env.production": "Production environment file",
    "/.env.backup": "Backup environment file",
    "/.git/config": "Git configuration — reveals repo URL, possibly credentials",
    "/.git/HEAD": "Git HEAD reference",
    "/.git/COMMIT_EDITMSG": "Latest git commit message",
    "/.gitignore": "Git ignore rules — reveals project structure",
    "/config.json": "Application configuration",
    "/config.yaml": "Application configuration",
    "/config.yml": "Application configuration",
    "/app.config.js": "Application config",
    "/database.yml": "Rails database configuration — DB credentials",
    "/database.json": "Database configuration",
    "/wp-config.php": "WordPress configuration",
    "/config/database.yml": "Rails DB config",
    "/config/secrets.yml": "Rails secrets",
    "/config/credentials.yml.enc": "Rails encrypted credentials",
    "/settings.py": "Django settings",
    "/local_settings.py": "Django local settings",
    "/api/v1/config": "API configuration endpoint",
    "/api/config": "API configuration",
    "/.DS_Store": "macOS directory metadata — reveals file structure",
    "/backup.sql": "Database backup",
    "/dump.sql": "Database dump",
    "/db.sql": "Database file",
    "/backup.zip": "Application backup",
    "/source.zip": "Source code archive",
    "/app.zip": "Application archive",
    "/robots.txt": "Robots file — reveals hidden paths (INFO only)",
    "/sitemap.xml": "Sitemap — reveals URL structure (INFO only)",
    "/.htaccess": "Apache config — may reveal rewrite rules, credentials",
    "/web.config": "IIS configuration",
    "/package.json": "Node.js project file — reveals dependencies, scripts",
    "/composer.json": "PHP Composer file",
    "/requirements.txt": "Python requirements",
    "/Gemfile": "Ruby Gemfile",
}

# ── Error-Triggering Paths ────────────────────────────────────────────────────
ERROR_TRIGGER_PATHS = [
    "/api/v1/users/INVALID_ID_THAT_SHOULD_NOT_EXIST_SECFORGE",
    "/api/v1/NONEXISTENT_ENDPOINT_SECFORGE/test",
    "/api/NONEXISTENT_SECFORGE",
]

# ── Stack Trace / Info Disclosure Signatures ──────────────────────────────────
STACK_TRACE_SIGNATURES = [
    r"traceback \(most recent call last\)",
    r"at [\w.$]+\([\w.]+:\d+\)",           # Java stack trace
    r"  File \"[^\"]+\", line \d+",         # Python traceback
    r"Stack trace:",
    r"NullPointerException",
    r"ArrayIndexOutOfBoundsException",
    r"undefined method",
    r"uninitialized constant",
    r"NameError:",
    r"NoMethodError:",
    r"TypeError:",
    r"RuntimeError:",
    r"ActiveRecord::",
    r"PG::SyntaxError",
    r"Doctrine\\",
    r"Illuminate\\",
    r"django\.core\.exceptions",
    r"fastapi\.exceptions",
    r"werkzeug\.exceptions",
    r"sqlalchemy\.exc",
]

INTERNAL_PATH_SIGNATURES = [
    r"/home/\w+/",
    r"/var/www/",
    r"/usr/local/",
    r"C:\\\\Users\\\\",
    r"C:\\\\inetpub\\\\",
    r"/root/",
    r"app\.py.*line \d+",
    r"server\.js.*line \d+",
]

VERSION_DISCLOSURE_SIGNATURES = [
    r"Server: Apache/[\d.]+",
    r"Server: nginx/[\d.]+",
    r"X-Powered-By: PHP/[\d.]+",
    r"X-Powered-By: Express",
    r"X-AspNet-Version:",
    r"X-AspNetMvc-Version:",
]


class MisconfigurationPlugin(BasePlugin):
    name = "misconfiguration"
    description = "Security misconfiguration: debug endpoints, sensitive files, verbose errors (OWASP API8)"
    owasp_id = "API8:2023"

    async def run(self, target: TargetConfig, client: SecForgeClient) -> list[Finding]:
        findings: list[Finding] = []

        # ── 1. Actuator Endpoints ──────────────────────────────────────────────
        actuator_findings = await _check_actuator(client)
        findings.extend(actuator_findings)

        # ── 2. Debug / Admin Endpoints ─────────────────────────────────────────
        debug_findings = await _check_debug_endpoints(client)
        findings.extend(debug_findings)

        # ── 3. Sensitive File Exposure ─────────────────────────────────────────
        file_findings = await _check_sensitive_files(client)
        findings.extend(file_findings)

        # ── 4. Verbose Error Responses ─────────────────────────────────────────
        error_findings = await _check_verbose_errors(client)
        findings.extend(error_findings)

        # ── 5. HTTP TRACE/TRACK ────────────────────────────────────────────────
        trace_finding = await _check_http_trace(client)
        if trace_finding:
            findings.append(trace_finding)

        return findings


async def _check_actuator(client: SecForgeClient) -> list[Finding]:
    findings: list[Finding] = []
    critical_exposed: list[tuple[str, str, Evidence]] = []
    sensitive_exposed: list[tuple[str, str, Evidence]] = []

    for path, description in ACTUATOR_ENDPOINTS.items():
        try:
            resp = await client.get(path)
            if resp.status_code in (200, 206):
                body = resp.text or ""
                ev = Evidence.from_httpx(resp.request, resp,
                    note=f"Actuator endpoint exposed: {description}")

                is_critical = any(word in path for word in ["env", "heapdump", "shutdown", "restart"])
                if is_critical:
                    critical_exposed.append((path, description, ev))
                else:
                    sensitive_exposed.append((path, description, ev))
        except httpx.HTTPError:
            continue

    if critical_exposed:
        ev_list = [ev for _, _, ev in critical_exposed]
        paths_str = "\n".join(f"  • {p} — {d}" for p, d, _ in critical_exposed)
        findings.append(Finding(
            title="CRITICAL: Spring Actuator Sensitive Endpoints Exposed",
            description=(
                "Critical Spring Actuator endpoints are publicly accessible in production. "
                "These endpoints can expose environment variables (including secrets), "
                "allow remote shutdown, or leak full heap memory dumps.\n\n"
                f"Exposed critical endpoints:\n{paths_str}"
            ),
            severity=Severity.CRITICAL,
            status=FindingStatus.CONFIRMED,
            owasp_id="API8:2023",
            plugin="misconfiguration",
            endpoint=critical_exposed[0][0],
            remediation=(
                "Restrict Actuator endpoints immediately. In application.properties:\n"
                "  management.endpoints.web.exposure.include=health,info\n"
                "  management.endpoint.env.enabled=false\n"
                "  management.endpoint.heapdump.enabled=false\n"
                "  management.endpoint.shutdown.enabled=false\n"
                "Additionally, place Actuator behind authentication and a separate port "
                "that is not publicly accessible."
            ),
            references=[
                "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html",
                "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
            ],
            evidence=ev_list,
        ))

    if sensitive_exposed:
        ev_list = [ev for _, _, ev in sensitive_exposed[:5]]
        paths_str = "\n".join(f"  • {p} — {d}" for p, d, _ in sensitive_exposed)
        findings.append(Finding(
            title="Spring Actuator Endpoints Exposed",
            description=(
                "Spring Actuator management endpoints are publicly accessible. "
                "These expose application internals, bean definitions, request mappings, "
                "and metrics that should not be visible to unauthenticated users.\n\n"
                f"Exposed endpoints:\n{paths_str}"
            ),
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            owasp_id="API8:2023",
            plugin="misconfiguration",
            endpoint=sensitive_exposed[0][0],
            remediation=(
                "Restrict Actuator exposure to health and info only:\n"
                "  management.endpoints.web.exposure.include=health,info\n"
                "Protect remaining endpoints with authentication and a non-public port."
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
            ],
            evidence=ev_list,
        ))

    return findings


async def _check_debug_endpoints(client: SecForgeClient) -> list[Finding]:
    findings: list[Finding] = []
    exposed: list[tuple[str, str, Evidence]] = []

    for path, description in DEBUG_ENDPOINTS.items():
        try:
            resp = await client.get(path)
            if resp.status_code in (200, 206) and len(resp.text or "") > 100:
                body = resp.text or ""
                # Avoid false positives — check that it's not a generic 200 (SPA index.html)
                if _is_meaningful_response(body, path):
                    ev = Evidence.from_httpx(resp.request, resp,
                        note=f"Debug/admin endpoint accessible: {description}")
                    exposed.append((path, description, ev))
        except httpx.HTTPError:
            continue

    if not exposed:
        return findings

    # Group by severity
    critical_paths = {"h2-console", "console", "actuator/env", "actuator/heapdump"}
    high_paths = {"admin", "admin/", "api/admin", "__admin__", "management", "graphiql", "playground"}

    for path, description, ev in exposed[:8]:
        path_clean = path.strip("/").lower()
        sev = (
            Severity.CRITICAL if any(c in path_clean for c in critical_paths)
            else Severity.HIGH if any(h in path_clean for h in high_paths)
            else Severity.MEDIUM
        )
        findings.append(Finding(
            title=f"Debug/Admin Endpoint Exposed: {path}",
            description=(
                f"The endpoint {path} is accessible in production.\n"
                f"Description: {description}\n\n"
                "Debug and admin endpoints left exposed in production are a common "
                "attack vector. Attackers enumerate these paths routinely."
            ),
            severity=sev,
            status=FindingStatus.CONFIRMED,
            owasp_id="API8:2023",
            plugin="misconfiguration",
            endpoint=path,
            remediation=(
                f"Disable or restrict access to {path} in production. "
                "Use environment-specific configuration to ensure debug "
                "endpoints are only available in development environments. "
                "If the endpoint must exist in production, protect it with "
                "authentication and IP allowlisting."
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
            ],
            evidence=[ev],
        ))

    return findings


async def _check_sensitive_files(client: SecForgeClient) -> list[Finding]:
    findings: list[Finding] = []
    exposed: list[tuple[str, str, str, Evidence]] = []  # path, desc, content_snippet, ev

    for path, description in SENSITIVE_FILES.items():
        try:
            resp = await client.get(path)
            if resp.status_code not in (200, 206):
                continue
            body = resp.text or ""
            if len(body) < 10:
                continue

            # Check for actual content signatures to avoid false positives
            is_real = _validate_sensitive_file(path, body)
            if not is_real:
                continue

            snippet = body[:200].replace("\n", " ")
            ev = Evidence.from_httpx(resp.request, resp,
                note=f"Sensitive file accessible: {description}\nContent preview: {snippet[:100]}...")
            exposed.append((path, description, snippet, ev))
        except httpx.HTTPError:
            continue

    for path, description, snippet, ev in exposed:
        # Determine severity by content sensitivity
        if any(x in path for x in [".env", "secrets", "credentials", "database", "config"]):
            sev = Severity.CRITICAL
        elif any(x in path for x in [".git", "backup", "dump", ".sql"]):
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM

        findings.append(Finding(
            title=f"Sensitive File Exposed: {path}",
            description=(
                f"The file {path} is publicly accessible.\n"
                f"Description: {description}\n\n"
                f"Content preview:\n{snippet[:300]}"
            ),
            severity=sev,
            status=FindingStatus.CONFIRMED,
            owasp_id="API8:2023",
            plugin="misconfiguration",
            endpoint=path,
            remediation=(
                f"Remove {path} from the web-accessible directory immediately. "
                "If this file contains credentials, rotate all secrets immediately. "
                "Add the file to your web server's deny list and review deployment "
                "processes to prevent future exposure."
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
            ],
            evidence=[ev],
        ))

    return findings


async def _check_verbose_errors(client: SecForgeClient) -> list[Finding]:
    findings: list[Finding] = []
    verbose_errors: list[tuple[str, str, Evidence]] = []

    for path in ERROR_TRIGGER_PATHS:
        try:
            resp = await client.get(path)
            body = resp.text or ""
            headers_str = str(dict(resp.headers))

            # Check for stack traces
            for sig in STACK_TRACE_SIGNATURES:
                if re.search(sig, body, re.IGNORECASE):
                    ev = Evidence.from_httpx(resp.request, resp,
                        note=f"Stack trace detected. Pattern: {sig}")
                    verbose_errors.append((path, f"Stack trace: {sig}", ev))
                    break

            # Check for internal path disclosure
            for sig in INTERNAL_PATH_SIGNATURES:
                if re.search(sig, body, re.IGNORECASE):
                    ev = Evidence.from_httpx(resp.request, resp,
                        note=f"Internal path disclosure. Pattern: {sig}")
                    verbose_errors.append((path, f"Internal path: {sig}", ev))
                    break

            # Check response headers for version disclosure
            for sig in VERSION_DISCLOSURE_SIGNATURES:
                if re.search(sig, headers_str, re.IGNORECASE):
                    ev = Evidence.from_httpx(resp.request, resp,
                        note=f"Version disclosure in headers. Pattern: {sig}")
                    match = re.search(sig, headers_str, re.IGNORECASE)
                    verbose_errors.append((path, f"Version header: {match.group(0) if match else sig}", ev))
                    break

        except httpx.HTTPError:
            continue

    if not verbose_errors:
        return findings

    # Group stack traces together
    stack_traces = [(p, d, ev) for p, d, ev in verbose_errors if "Stack trace" in d or "Internal" in d]
    version_headers = [(p, d, ev) for p, d, ev in verbose_errors if "Version" in d]

    if stack_traces:
        ev_list = [ev for _, _, ev in stack_traces[:3]]
        findings.append(Finding(
            title="Verbose Error Responses — Stack Traces Exposed",
            description=(
                "API error responses include full stack traces or internal path information. "
                "This reveals application framework, file paths, library versions, and "
                "code structure — valuable intelligence for an attacker.\n\n"
                "Detected in responses to:\n"
                + "\n".join(f"  • {p} ({d})" for p, d, _ in stack_traces)
            ),
            severity=Severity.MEDIUM,
            status=FindingStatus.CONFIRMED,
            owasp_id="API8:2023",
            plugin="misconfiguration",
            endpoint=stack_traces[0][0],
            remediation=(
                "Configure your application to return generic error messages in production. "
                "Log detailed errors server-side, not in HTTP responses. "
                "In production, set DEBUG=False (Django/Flask), "
                "app.config['PROPAGATE_EXCEPTIONS'] = False (Flask), "
                "or configure a custom error handler that returns generic messages."
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
            ],
            evidence=ev_list,
        ))

    if version_headers:
        ev_list = [ev for _, _, ev in version_headers[:3]]
        findings.append(Finding(
            title="Version Disclosure in HTTP Headers",
            description=(
                "HTTP response headers reveal the exact version of the web server or "
                "application framework. This information helps attackers identify "
                "known CVEs for your specific version.\n\n"
                "Disclosed versions:\n"
                + "\n".join(f"  • {d}" for _, d, _ in version_headers)
            ),
            severity=Severity.LOW,
            status=FindingStatus.CONFIRMED,
            owasp_id="API8:2023",
            plugin="misconfiguration",
            endpoint=version_headers[0][0],
            remediation=(
                "Remove or suppress version information from HTTP headers:\n"
                "  nginx: server_tokens off;\n"
                "  Apache: ServerTokens Prod; ServerSignature Off\n"
                "  Express: app.disable('x-powered-by');\n"
                "  PHP: expose_php = Off (php.ini)"
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
            ],
            evidence=ev_list,
        ))

    return findings


async def _check_http_trace(client: SecForgeClient) -> Optional[Finding]:
    """Check if HTTP TRACE/TRACK methods are enabled (Cross-Site Tracing)."""
    for method in ("TRACE", "TRACK"):
        try:
            resp = await client.request(method, "/")
            if resp.status_code == 200:
                body = resp.text or ""
                # TRACE echoes back the request headers in the response body
                if "TRACE" in body or "Authorization" in body or len(body) > 20:
                    ev = Evidence.from_httpx(resp.request, resp,
                        note=f"HTTP {method} enabled — request headers echoed back")
                    return Finding(
                        title=f"HTTP {method} Method Enabled (Cross-Site Tracing)",
                        description=(
                            f"The HTTP {method} method is enabled on this server. "
                            "TRACE echoes back all request headers in the response body, "
                            "including Authorization headers and cookies. Combined with "
                            "XSS vulnerabilities, this enables Cross-Site Tracing (XST) — "
                            "stealing authentication credentials from victim browsers."
                        ),
                        severity=Severity.LOW,
                        status=FindingStatus.CONFIRMED,
                        owasp_id="API8:2023",
                        plugin="misconfiguration",
                        endpoint="/",
                        remediation=(
                            "Disable TRACE and TRACK methods in your web server:\n"
                            "  nginx: add to server block: if ($request_method ~ ^(TRACE|TRACK)$) { return 405; }\n"
                            "  Apache: TraceEnable Off (httpd.conf)\n"
                            "  Express: Use a middleware to block TRACE requests."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                            "https://owasp.org/www-community/attacks/Cross_Site_Tracing",
                        ],
                        evidence=[ev],
                    )
        except httpx.HTTPError:
            continue
    return None


def _is_meaningful_response(body: str, path: str) -> bool:
    """Check if a 200 response is actually the debug/admin page, not an SPA fallback."""
    body_lower = body.lower()
    path_lower = path.lower()

    # SPA fallback usually contains the app's HTML
    if "<html" in body_lower and "react" in body_lower:
        return False
    if "<html" in body_lower and "angular" in body_lower:
        return False

    # Actuator/debug responses are typically JSON
    if "actuator" in path_lower or "debug" in path_lower:
        return body.strip().startswith("{") or body.strip().startswith("[")

    # Admin interfaces have specific markers
    if "admin" in path_lower:
        return any(m in body_lower for m in ["login", "admin", "dashboard", "manage"])

    # Swagger/GraphiQL
    if any(x in path_lower for x in ["swagger", "graphiql", "playground"]):
        return any(m in body_lower for m in ["swagger", "graphql", "openapi"])

    return len(body) > 200


def _validate_sensitive_file(path: str, body: str) -> bool:
    """Validate that a response actually contains sensitive content, not a 200 redirect."""
    path_lower = path.lower()
    body_lower = body.lower()

    if ".env" in path_lower:
        return any(x in body for x in ["=", "DB_", "SECRET", "KEY", "TOKEN", "PASSWORD", "HOST"])
    if ".git" in path_lower:
        if "config" in path_lower:
            return "[core]" in body or "[remote" in body
        return True
    if ".sql" in path_lower or "dump" in path_lower or "backup" in path_lower:
        return any(x in body_lower for x in ["create table", "insert into", "drop table", "mysqldump"])
    if "package.json" in path_lower:
        return '"name"' in body and '"version"' in body
    if "requirements.txt" in path_lower:
        return "==" in body or ">=" in body
    if "config" in path_lower:
        return any(x in body_lower for x in ["password", "secret", "key", "token", "host", "database"])
    if "robots.txt" in path_lower:
        return "user-agent" in body_lower or "disallow" in body_lower
    return len(body) > 50
