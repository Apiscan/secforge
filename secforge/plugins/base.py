"""
BasePlugin — the interface every ApiScan check must implement.

Adding a new check = subclass BasePlugin, implement run().
The plugin system is designed to be zero-coupling: plugins don't
know about each other, don't share state, and are fully composable.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from secforge.core.client import SecForgeClient
    from secforge.models.finding import Finding
    from secforge.models.target import TargetConfig


class BasePlugin(ABC):
    # Class-level metadata — required on every plugin
    name: str = ""
    description: str = ""
    owasp_id: str | None = None

    @abstractmethod
    async def run(self, target: "TargetConfig", client: "SecForgeClient") -> list["Finding"]:
        """
        Execute this security check against the target.

        Args:
            target: The target configuration (URL, auth, headers, etc.)
            client: The authenticated async HTTP client

        Returns:
            List of Finding objects. Empty list = clean.

        Rules:
            - Never raise unhandled exceptions — catch and return empty list or INFO finding
            - Every non-INFO finding must carry at least one Evidence record
            - CONFIRMED findings must have evidence with a response_status
        """
        ...

    def __repr__(self) -> str:
        return f"<Plugin: {self.name}>"
