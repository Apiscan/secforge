"""Plugin registry — maps plugin names to plugin classes."""

from secforge.plugins.rest.headers import HeadersPlugin
from secforge.plugins.rest.tls import TLSPlugin
from secforge.plugins.rest.cors import CORSPlugin
from secforge.plugins.rest.bola import BOLAPlugin
from secforge.plugins.rest.auth import AuthPlugin
from secforge.plugins.rest.rate_limit import RateLimitPlugin
from secforge.plugins.rest.jwt import JWTPlugin
from secforge.plugins.rest.oauth2 import OAuth2Plugin
from secforge.plugins.rest.apikey import APIKeyPlugin
from secforge.plugins.graphql.scanner import GraphQLPlugin
from secforge.plugins.rest.ssrf import SSRFPlugin
from secforge.plugins.rest.injection import InjectionPlugin
from secforge.plugins.rest.mass_assignment import MassAssignmentPlugin
from secforge.plugins.rest.misconfiguration import MisconfigurationPlugin

ALL_PLUGINS: dict[str, type] = {
    # Phase 1 — Foundation
    "tls": TLSPlugin,
    "headers": HeadersPlugin,
    # Phase 2 — OWASP API Top 10
    "cors": CORSPlugin,
    "bola": BOLAPlugin,
    "auth": AuthPlugin,
    "rate_limit": RateLimitPlugin,
    # Phase 3 — Auth Deep Dive
    "jwt": JWTPlugin,
    "oauth2": OAuth2Plugin,
    "apikey": APIKeyPlugin,
    # Phase 4 — Protocol Support
    "graphql": GraphQLPlugin,
    # Phase 5 — SSRF (OWASP API7)
    "ssrf": SSRFPlugin,
    # Phase 6 — Deep Scanning
    "injection": InjectionPlugin,
    "mass_assignment": MassAssignmentPlugin,
    "misconfiguration": MisconfigurationPlugin,
}

DEFAULT_PLUGINS = list(ALL_PLUGINS.keys())
