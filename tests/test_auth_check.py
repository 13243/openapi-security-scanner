"""Unit tests for AuthCheck with a fake executor."""
from dataclasses import dataclass

from apiconf.checks.auth import AuthCheck
from apiconf.checks.base import CheckContext
from apiconf.openapi_parser import Operation


@dataclass
class FakeResponse:
    status_code: int


class FakeExecutor:
    def __init__(self, code: int):
        self.code = code
        self.calls = []

    def request(self, method, url, headers=None):
        self.calls.append((method, url, headers))
        return FakeResponse(self.code)


def make_ctx(code: int, security):
    op = Operation(method="GET", path="/x", operation_id=None, security=security)
    return CheckContext(
        executor=FakeExecutor(code),
        operation=op,
        effective_security=security or [],
        url="http://t/x",
        config={"auth": {"invalid_token": "Bearer bad"}},
    )


def test_m1_declared_protected_but_open():
    findings = AuthCheck().run(make_ctx(200, [{"bearer": []}]))
    assert any(f.mismatch_id == "M1" for f in findings)


def test_m2_declared_open_but_protected():
    findings = AuthCheck().run(make_ctx(401, []))
    assert any(f.mismatch_id == "M2" for f in findings)


def test_ok_protected_requires_auth():
    findings = AuthCheck().run(make_ctx(401, [{"bearer": []}]))
    assert findings == []


def test_ok_open_is_open():
    findings = AuthCheck().run(make_ctx(200, []))
    assert findings == []
