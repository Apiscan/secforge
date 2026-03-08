"""
Scope file — pre-authorized target registry for CI/CD pipelines.

Instead of interactive prompts, teams maintain a scope.yml that lists
every authorized target. The CI pipeline passes --scope-file scope.yml
and ApiScan verifies the scan target is in the authorized list.

Format:
  authorized_targets:
    - url: https://api.example.com
      authorized_by: "Security Team"
      date: "2026-03-01"
      notes: "Quarterly pentest — authorized via security-ticket-123"
      environments: [staging, production]
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import yaml

from secforge.models.target import TargetConfig, ScopeConfig


class ScopeFile:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._data: dict = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            raise FileNotFoundError(f"Scope file not found: {self.path}")
        with self.path.open() as f:
            self._data = yaml.safe_load(f) or {}

    def is_authorized(self, url: str) -> tuple[bool, Optional[dict]]:
        """
        Check if a URL is in the authorized targets list.
        Returns (authorized, metadata_dict).
        Matches on hostname + path prefix — scheme and port are normalized.
        """
        targets = self._data.get("authorized_targets", [])
        parsed = urlparse(url)
        target_host = parsed.netloc.lower()
        target_path = parsed.path.rstrip("/") or "/"

        for entry in targets:
            entry_url = entry.get("url", "")
            ep = urlparse(entry_url)
            entry_host = ep.netloc.lower()
            entry_path = ep.path.rstrip("/") or "/"

            # Match if host matches and entry path is a prefix of scan path
            if entry_host == target_host and target_path.startswith(entry_path):
                return True, entry

        return False, None

    def authorize_target(self, target: TargetConfig) -> bool:
        """
        Check scope file and update target's ScopeConfig if authorized.
        Returns True if target is authorized.
        """
        authorized, entry = self.is_authorized(target.url)
        if authorized and entry:
            target.scope = ScopeConfig(
                authorized=True,
                acknowledged_by=entry.get("authorized_by", "scope-file"),
                date=entry.get("date", ""),
                notes=entry.get("notes", f"Authorized via scope file: {self.path}"),
            )
        return authorized


SCOPE_FILE_TEMPLATE = """\
# ApiScan Scope File
# List all targets your team is authorized to scan.
# Use with: secforge scan --scope-file scope.yml --url https://api.example.com

authorized_targets:
  - url: https://api.example.com
    authorized_by: "Security Team"
    date: "2026-03-01"
    environments: [staging, production]
    notes: "Authorized via security-ticket-123 — quarterly API pentest"

  - url: https://staging.api.example.com
    authorized_by: "DevOps Lead"
    date: "2026-03-01"
    environments: [staging]
    notes: "Staging environment — CI/CD automated scans approved"

  # Add more targets below
"""
