"""Parse OpenAPI specs and extract security declarations per operation."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Operation:
    method: str
    path: str
    operation_id: str | None
    security: list[dict[str, list[str]]] | None
    parameters: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class SpecInfo:
    raw: dict[str, Any]
    global_security: list[dict[str, list[str]]] | None
    operations: list[Operation]


def load_spec(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(text)
    return json.loads(text)


def extract_operations(spec: dict[str, Any]) -> SpecInfo:
    global_security = spec.get("security")
    operations: list[Operation] = []
    for path, methods in (spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            if not isinstance(op, dict):
                continue
            operations.append(Operation(
                method=method.upper(),
                path=path,
                operation_id=op.get("operationId"),
                security=op.get("security"),
                parameters=op.get("parameters", []),
            ))
    return SpecInfo(raw=spec, global_security=global_security, operations=operations)


def effective_security(op: Operation, info: SpecInfo) -> list[dict[str, list[str]]]:
    if op.security is None:
        return info.global_security or []
    return op.security
