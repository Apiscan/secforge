"""Finding model — the core output unit of every SecForge plugin."""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel

from .enums import Severity, FindingStatus
from .evidence import Evidence


class Finding(BaseModel):
    """
    A single security finding with full evidence chain.
    Rules:
      - CONFIRMED requires at least one Evidence with a response_status
      - PROBABLE requires at least one Evidence
      - SPECULATIVE can have zero evidence (flag for manual review only)
    """
    title: str
    description: str
    severity: Severity
    status: FindingStatus

    owasp_id: Optional[str] = None        # e.g. "API1:2023"
    cwe_id: Optional[str] = None          # e.g. "CWE-639"
    cvss_score: Optional[float] = None

    evidence: list[Evidence] = []
    remediation: str = ""
    references: list[str] = []
    plugin: str = ""                       # Which plugin generated this
    endpoint: str = ""                     # Affected endpoint

    @property
    def label(self) -> str:
        return f"{self.severity.emoji} [{self.severity}] {self.title}"

    def is_valid(self) -> tuple[bool, str]:
        """Validate evidence requirements per status tier."""
        if self.status == FindingStatus.CONFIRMED and not any(
            e.response_status is not None for e in self.evidence
        ):
            return False, "CONFIRMED findings require at least one Evidence with a response"
        if self.status == FindingStatus.PROBABLE and not self.evidence:
            return False, "PROBABLE findings require at least one Evidence record"
        return True, ""
