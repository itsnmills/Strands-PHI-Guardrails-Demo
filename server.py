#!/usr/bin/env python3
"""PHI Guardrails web console."""
from __future__ import annotations

import traceback
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from core import (
    api_key_configured,
    audit_sink,
    build_agent,
    format_provider_error,
    public_config,
    steering_sink,
)

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"

app = FastAPI(title="PHI Guardrails", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")

_sessions: dict[str, dict] = {}
_agent = None


class RunRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=4000)


def _session_id(request: Request) -> str:
    return request.cookies.get("phi_session") or str(uuid.uuid4())


def _session(sid: str) -> dict:
    return _sessions.setdefault(sid, {"audit": [], "last": None})


def _cookie(response: JSONResponse, request: Request, sid: str) -> JSONResponse:
    if "phi_session" not in request.cookies:
        response.set_cookie("phi_session", sid, httponly=True, samesite="lax")
    return response


def _get_agent():
    global _agent
    if _agent is None:
        _agent = build_agent()
    return _agent


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/config")
def config(request: Request):
    sid = _session_id(request)
    state = _session(sid)
    payload = public_config()
    payload["audit"] = list(reversed(state["audit"]))
    if state["last"]:
        payload["last"] = state["last"]
    return _cookie(JSONResponse(payload), request, sid)


@app.post("/api/run")
def run_agent(body: RunRequest, request: Request):
    sid = _session_id(request)
    state = _session(sid)
    if not api_key_configured():
        payload = {
            "ok": False,
            "status": "ERROR",
            "response": "API key not configured. Add OPENCODE_GO_API_KEY to .env. See the README.",
            "steering": [],
            "audit": list(reversed(state["audit"])),
        }
        return _cookie(JSONResponse(payload, status_code=400), request, sid)

    events: list[dict] = []
    run_log: list[dict] = []

    def sink(entry: dict) -> None:
        state["audit"].append(entry)
        run_log.append(entry)

    token_audit = audit_sink.set(sink)
    token_steer = steering_sink.set(events)
    try:
        agent = _get_agent()
        result = agent(body.prompt.strip())
        text = str(result)
        blocked = any(event.get("event") == "BLOCKED" for event in events) or any(
            entry.get("blocked") for entry in run_log
        )
        payload = {
            "ok": True,
            "status": "BLOCKED" if blocked else "READY",
            "response": text,
            "steering": events,
            "audit": list(reversed(state["audit"])),
        }
    except Exception as exc:
        traceback.print_exc()
        payload = {
            "ok": False,
            "status": "ERROR",
            "response": format_provider_error(exc),
            "steering": events,
            "audit": list(reversed(state["audit"])),
        }
    finally:
        audit_sink.reset(token_audit)
        steering_sink.reset(token_steer)

    state["last"] = {
        "prompt": body.prompt.strip(),
        "status": payload["status"],
        "response": payload["response"],
        "steering": payload["steering"],
        "ok": payload["ok"],
    }
    return _cookie(JSONResponse(payload, status_code=200 if payload["ok"] else 500), request, sid)


@app.post("/api/clear")
def clear_session(request: Request):
    sid = _session_id(request)
    _sessions[sid] = {"audit": [], "last": None}
    return _cookie(
        JSONResponse({"ok": True, "audit": [], "steering": [], "response": ""}),
        request,
        sid,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server:app", host="0.0.0.0", port=8502, reload=False)
