"""Local intentionally-inconsistent mock API for experiments."""
from fastapi import FastAPI, Header, HTTPException

app = FastAPI()


@app.get("/public")
def public():
    return {"ok": True}


@app.get("/private")
def private(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer good"):
        raise HTTPException(401, "unauthorized")
    return {"secret": "data"}


@app.get("/broken-open")
def broken_open():
    return {"leaked": "data"}


@app.get("/broken-protected")
def broken_protected(authorization: str | None = Header(default=None)):
    raise HTTPException(401, "unauthorized")


@app.get("/accepts-bad-token")
def accepts_bad_token(authorization: str | None = Header(default=None)):
    if not authorization:
        raise HTTPException(401, "unauthorized")
    return {"ok": True}
