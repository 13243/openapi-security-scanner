"""Base plugin interface for conformance checks."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    check: str
    severity: str
    endpoint: str
    mismatch_id: str
    expected: str
    actual: str
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckContext:
    executor: Any
    operation: Any
    effective_security: list[dict[str, list[str]]]
    url: str
    config: dict[str, Any]


class Check(ABC):
    name: str = "base"

    @abstractmethod
    def run(self, ctx: CheckContext) -> list[Finding]:
        ...
