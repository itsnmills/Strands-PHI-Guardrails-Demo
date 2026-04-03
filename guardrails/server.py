"""
guardrails/server.py
────────────────────
Local FastAPI server — run this on dario-vm so any service on the box
can hit the guardrail engine over HTTP before making an external call.

Start:
    uvicorn guardrails.server:app --host 127.0.0.1 --port 8100

Or as a systemd service (see guardrails/guardrails.service).

POST /check
    → runs all 6 HIPAA control layers
    → returns JSON with blocked / reason / redacted_payload etc.

GET /health
    → liveness probe

The server is localhost-only (127.0.0.1) by design —
it is not a public API, it is a local pre-flight sidecar.

Install:
    pip install fastapi uvicorn
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
import logging

from .engine import check, CheckResult, GuardrailBlocked

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("guardrails")

app = FastAPI(
    title="PHI Guardrails",
    description="HIPAA pre-flight check engine — local sidecar for any service that handles PHI",
    version="2.0.0",
    docs_url="/docs",
)


# ── Request / Response models ─────────────────────────────────────────────────

class CheckRequest(BaseModel):
    role: str = Field(..., description="Clinical role: physician | nurse | billing_staff | researcher | it_admin | external_auditor")
    purpose: str = Field(..., description="HIPAA purpose code: TREATMENT | PAYMENT | OPERATIONS | RESEARCH | LEGAL | PUBLIC_HEALTH | HANDOFF | AUDIT")
    tool: str = Field(..., description="The action being requested, e.g. 'call_llm', 'send_email', 'query_patient_record'")
    patient_id: str = Field("", description="Patient identifier for sensitivity lookup")
    vendor_id: str = Field("", description="Destination system identifier (for BAA check)")
    payload: str = Field("", description="The text or data being processed or sent — scanned for raw PHI")
    justification: str = Field("", description="Free-text justification (required for some purpose codes)")
    patient_sensitivity: Optional[str] = Field(None, description="Override sensitivity lookup: STANDARD | SENSITIVE | RESTRICTED")

    model_config = {"json_schema_extra": {"example": {
        "role": "nurse",
        "purpose": "TREATMENT",
        "tool": "query_patient_record",
        "patient_id": "P003",
        "payload": "Pull the full record for Sarah Connor — I need to review her psych history.",
    }}}


class CheckResponse(BaseModel):
    blocked: bool
    rule: str
    reason: str
    role: str
    purpose: str
    tool: str
    risk_score: float
    phi_types: list[str]
    redacted_payload: str
    timestamp: str
    layer: int
    # Convenience fields
    allowed: bool
    safe_payload: str   # alias for redacted_payload


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "phi-guardrails"}


@app.post("/check", response_model=CheckResponse)
def run_check(req: CheckRequest) -> CheckResponse:
    """
    Run the 6-layer HIPAA guardrail check.

    Returns immediately with blocked=true/false. ~1ms latency.
    If blocked=true, do NOT proceed with the downstream action.
    Use redacted_payload / safe_payload for a PHI-masked version of the input.
    """
    try:
        result: CheckResult = check(
            role=req.role,
            purpose=req.purpose,
            tool=req.tool,
            patient_id=req.patient_id,
            vendor_id=req.vendor_id,
            payload=req.payload,
            justification=req.justification,
            patient_sensitivity=req.patient_sensitivity,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    if result.blocked:
        log.warning(
            "BLOCKED | role=%s purpose=%s tool=%s rule=%s",
            req.role, req.purpose, req.tool, result.rule,
        )
    else:
        log.info(
            "ALLOWED | role=%s purpose=%s tool=%s risk=%.2f",
            req.role, req.purpose, req.tool, result.risk_score,
        )

    return CheckResponse(
        **result.to_dict(),
        allowed=not result.blocked,
        safe_payload=result.redacted_payload,
    )


@app.post("/redact")
def redact_only(body: dict) -> dict:
    """
    Lightweight endpoint — just scan and redact text, no policy check.
    Use this before logging anything that might contain PHI.

    POST /redact
    { "text": "Patient Jane Doe SSN 123-45-6789 called today" }
    → { "redacted": "Patient [NAME-FULL] SSN [SSN] called today", "risk_score": 0.97, "phi_types": ["ssn", "name_full"] }
    """
    from .engine import _detect_phi
    text = body.get("text", "")
    result = _detect_phi(text)
    return {
        "redacted": result.redacted_text,
        "risk_score": result.risk_score,
        "phi_types": result.all_types,
        "phi_found": result.phi_found,
    }
