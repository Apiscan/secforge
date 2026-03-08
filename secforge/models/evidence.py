"""Evidence model — every finding must carry proof."""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel


class Evidence(BaseModel):
    """
    A captured request/response pair that proves a finding exists.
    ApiScan never reports without evidence — this is the contract.
    """
    request_method: str = ""
    request_url: str = ""
    request_headers: dict[str, str] = {}
    request_body: Optional[str] = None

    response_status: Optional[int] = None
    response_headers: dict[str, str] = {}
    response_body_snippet: Optional[str] = None  # First 500 chars max

    note: str = ""  # Human-readable explanation of what this evidence shows

    @classmethod
    def from_httpx(cls, request, response, note: str = "", body_limit: int = 500) -> "Evidence":
        """Build Evidence from an httpx request/response pair."""
        req_headers = dict(request.headers) if request else {}
        resp_headers = dict(response.headers) if response else {}

        body_snippet: Optional[str] = None
        if response is not None:
            try:
                raw = response.text
                body_snippet = raw[:body_limit] + ("…" if len(raw) > body_limit else "")
            except Exception:
                body_snippet = "<binary or unreadable body>"

        try:
            req_body = request.content.decode(errors="replace") if request and request.content else None
        except Exception:
            req_body = "<streaming body — not captured>"

        return cls(
            request_method=str(request.method) if request else "",
            request_url=str(request.url) if request else "",
            request_headers=req_headers,
            request_body=req_body,
            response_status=response.status_code if response else None,
            response_headers=resp_headers,
            response_body_snippet=body_snippet,
            note=note,
        )

    @classmethod
    def observed(cls, note: str, url: str = "", method: str = "GET", **kwargs) -> "Evidence":
        """Create an Evidence record from an observation (no live request needed)."""
        return cls(request_method=method, request_url=url, note=note, **kwargs)
