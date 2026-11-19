"""MVP check: authentication declaration conformance (M1, M2, M3)."""
from __future__ import annotations

from .base import Check, CheckContext, Finding


class AuthCheck(Check):
    name = "auth"

    def run(self, ctx: CheckContext) -> list[Finding]:
        op = ctx.operation
        endpoint = f"{op.method} {op.path}"
        declared_protected = bool(ctx.effective_security)
        findings: list[Finding] = []

        try:
            r = ctx.executor.request(op.method, ctx.url, headers={})
        except Exception as e:
            return [Finding(
                check=self.name, severity="low", endpoint=endpoint,
                mismatch_id="M4", expected="reachable",
                actual=f"error: {e}", message="request failed",
            )]

        code = r.status_code

        if declared_protected and code not in (401, 403):
            findings.append(Finding(
                check=self.name, severity="high", endpoint=endpoint,
                mismatch_id="M1",
                expected="401/403 without auth",
                actual=f"{code} without auth",
                message="Declared protected endpoint is reachable without authentication.",
            ))
        elif (not declared_protected) and code in (401, 403):
            findings.append(Finding(
                check=self.name, severity="medium", endpoint=endpoint,
                mismatch_id="M2",
                expected="not 401/403 without auth (declared open)",
                actual=f"{code} without auth",
                message="Declared open endpoint unexpectedly requires authentication.",
            ))

        if declared_protected and code in (401, 403):
            bad = ctx.config.get("auth", {}).get("invalid_token")
            if bad:
                try:
                    r2 = ctx.executor.request(op.method, ctx.url, headers={"Authorization": bad})
                    if r2.status_code not in (401, 403):
                        findings.append(Finding(
                            check=self.name, severity="high", endpoint=endpoint,
                            mismatch_id="M3",
                            expected="401/403 with invalid token",
                            actual=f"{r2.status_code} with invalid token",
                            message="Invalid token is accepted.",
                        ))
                except Exception:
                    pass

        return findings
