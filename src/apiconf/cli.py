"""CLI entry point."""
from __future__ import annotations

import json
from pathlib import Path

import typer

from .checks.auth import AuthCheck
from .checks.base import CheckContext
from .executor import Executor
from .openapi_parser import effective_security, extract_operations, load_spec
from .request_builder import build_url
from .report import write_json

app = typer.Typer(help="OpenAPI security-declaration conformance scanner (MVP).")

CHECKS = [AuthCheck()]


@app.command()
def scan(
    spec: Path = typer.Option(..., "--spec", help="OpenAPI file"),
    base_url: str = typer.Option(..., "--base-url"),
    out: Path = typer.Option(Path("report.json"), "--out"),
    config_file: Path | None = typer.Option(None, "--config"),
    method_filter: str = typer.Option("GET", "--methods"),
) -> None:
    allowed = {m.strip().upper() for m in method_filter.split(",")}
    cfg: dict = {}
    if config_file and Path(config_file).exists():
        cfg = json.loads(Path(config_file).read_text(encoding="utf-8"))

    info = extract_operations(load_spec(spec))
    ex = Executor(base_url)
    findings = []
    try:
        for op in info.operations:
            if op.method not in allowed:
                continue
            url = build_url(base_url, op.path, op)
            ctx = CheckContext(
                executor=ex,
                operation=op,
                effective_security=effective_security(op, info),
                url=url,
                config=cfg,
            )
            for check in CHECKS:
                findings.extend(check.run(ctx))
    finally:
        ex.close()

    write_json(findings, out)
    typer.echo(f"Scan complete. {len(findings)} findings -> {out}")


if __name__ == "__main__":
    app()
