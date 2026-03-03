"""Target configuration model."""

from __future__ import annotations

from typing import Optional, Literal
from pydantic import BaseModel, field_validator


class AuthConfig(BaseModel):
    type: Literal["bearer", "api_key", "basic", "none"] = "none"

    # Bearer / API key
    token: Optional[str] = None
    header: Optional[str] = None   # Custom header name for api_key (default: Authorization)
    value: Optional[str] = None    # Value for api_key auth

    # Basic auth
    username: Optional[str] = None
    password: Optional[str] = None

    def build_headers(self) -> dict[str, str]:
        """Return headers dict to inject for this auth config."""
        if self.type == "bearer" and self.token:
            return {"Authorization": f"Bearer {self.token}"}
        if self.type == "api_key":
            key = self.header or "X-API-Key"
            val = self.value or ""
            return {key: val}
        return {}

    def build_auth_tuple(self) -> Optional[tuple[str, str]]:
        """Return (username, password) for Basic auth, or None."""
        if self.type == "basic" and self.username:
            return (self.username, self.password or "")
        return None


class ScopeConfig(BaseModel):
    authorized: bool = False
    acknowledged_by: Optional[str] = None
    date: Optional[str] = None
    notes: Optional[str] = None


class ScanOptions(BaseModel):
    timeout: int = 30
    rate_limit: int = 10        # requests/second max
    follow_redirects: bool = True
    verify_ssl: bool = True
    max_redirects: int = 5
    user_agent: str = "SecForge/0.1 (authorized-pentest)"


class TargetConfig(BaseModel):
    url: str
    name: str = ""
    auth: AuthConfig = AuthConfig()
    # Optional second user auth — enables real cross-user BOLA/IDOR testing.
    # user_a_auth is an alias for auth (the primary token).
    # Provide user_b_auth to allow SecForge to attempt accessing user A's
    # resources as user B, confirming object-level authorization failures.
    user_b_auth: Optional[AuthConfig] = None
    scope: ScopeConfig = ScopeConfig()
    headers: dict[str, str] = {}
    options: ScanOptions = ScanOptions()

    @field_validator("url")
    @classmethod
    def normalize_url(cls, v: str) -> str:
        v = v.rstrip("/")
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        return v

    @property
    def host(self) -> str:
        from urllib.parse import urlparse
        return urlparse(self.url).netloc

    @property
    def is_https(self) -> bool:
        return self.url.startswith("https://")
