# apiconf

Extensible OpenAPI security-declaration conformance scanner. MVP checks
authentication declarations vs actual behavior.

## Install

    pip install -e .

## Tests

    pytest

## Mock API

    python -m uvicorn tests.mock_api:app --port 8000

## Scan

    apiconf scan --spec tests/fixtures/openapi.yaml --base-url http://localhost:8000 --config examples/config.json --out report.json
