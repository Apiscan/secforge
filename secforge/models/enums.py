"""Core enumerations for SecForge findings."""

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def emoji(self) -> str:
        return {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "⚪",
        }[self.value]

    @property
    def order(self) -> int:
        """Lower = more severe (for sorting)."""
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[self.value]


class FindingStatus(str, Enum):
    CONFIRMED = "CONFIRMED"    # Exploited / verified with a real response
    PROBABLE = "PROBABLE"      # Strong evidence, not fully exploited
    SPECULATIVE = "SPECULATIVE"  # Flag for manual review


class Protocol(str, Enum):
    REST = "REST"
    GRAPHQL = "GraphQL"
    GRPC = "gRPC"
    WEBSOCKET = "WebSocket"
