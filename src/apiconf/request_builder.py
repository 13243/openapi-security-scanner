"""Build safe test requests from Operation metadata."""
from __future__ import annotations

import re
from typing import Any

from .openapi_parser import Operation


def _dummy_for_schema(schema: dict[str, Any]) -> Any:
    t = schema.get("type", "string")
    if t == "integer":
        return 1
    if t == "number":
        return 1.0
    if t == "boolean":
        return True
    if t == "array":
        return []
    if t == "object":
        return {}
    return "test"


def _path_params(path: str) -> list[str]:
    return re.findall(r"\{([^}]+)\}", path)


def fill_path(path: str, op: Operation) -> str:
    schemas: dict[str, dict[str, Any]] = {}
    for p in op.parameters:
        if p.get("in") == "path" and "name" in p:
            schemas[p["name"]] = p.get("schema", {})
    names = list(schemas) or _path_params(path)
    out = path
    for name in names:
        out = out.replace("{" + name + "}", str(_dummy_for_schema(schemas.get(name, {}))))
    return out


def build_url(base_url: str, path: str, op: Operation) -> str:
    return base_url.rstrip("/") + fill_path(path, op)
