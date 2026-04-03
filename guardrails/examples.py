"""
guardrails/examples.py
──────────────────────
Copy-paste patterns for the three most common use cases.

Pattern: run check() BEFORE the external call.
If blocked → abort. If allowed → proceed.
The guardrail runs in ~1ms so it adds no meaningful latency.

Run this file to see all examples:
    python -m guardrails.examples
"""

from __future__ import annotations
import json
from guardrails import check, GuardrailBlocked


# ─────────────────────────────────────────────────────────────────────────────
# Pattern 1 — LLM call with patient context
# ─────────────────────────────────────────────────────────────────────────────

def call_llm_with_guard(
    role: str,
    purpose: str,
    patient_id: str,
    prompt: str,
) -> str:
    """
    Check before sending patient context to an LLM endpoint.
    If the prompt contains raw PHI (SSN, DOB, etc.), block it.
    Return the LLM response only if the check passes.
    """
    result = check(
        role=role,
        purpose=purpose,
        tool="call_llm",
        patient_id=patient_id,
        payload=prompt,
    )

    if result.blocked:
        # Option A: raise and let the caller handle it
        raise GuardrailBlocked(result)

    # Option B (shown below): proceed with the safe (redacted) payload
    safe_prompt = result.redacted_payload  # PHI replaced with [SSN], [DOB], etc.

    # --- replace with your actual LLM call ---
    print(f"  → LLM call ALLOWED (risk score: {result.risk_score:.2f})")
    print(f"  → Sending: {safe_prompt[:120]}...")
    return f"[simulated LLM response for: {safe_prompt[:60]}]"
    # -----------------------------------------


# ─────────────────────────────────────────────────────────────────────────────
# Pattern 2 — Email / Slack / webhook send
# ─────────────────────────────────────────────────────────────────────────────

def send_email_with_guard(
    role: str,
    purpose: str,
    vendor_id: str,
    subject: str,
    body: str,
    justification: str = "Routine communication",
) -> bool:
    """
    Check before sending an email that might contain patient data.
    Blocks if: vendor not BAA-covered, or body contains raw PHI.
    """
    result = check(
        role=role,
        purpose=purpose,
        tool="send_email",
        vendor_id=vendor_id,
        payload=body,
        justification=justification,
    )

    if result.blocked:
        print(f"  ✗ EMAIL BLOCKED: [{result.rule}]")
        print(f"    Reason: {result.reason}")
        return False

    # --- replace with your actual email send ---
    print(f"  ✓ EMAIL ALLOWED — sending to {vendor_id}")
    print(f"    Subject: {subject}")
    return True
    # -------------------------------------------


def send_slack_with_guard(
    role: str,
    purpose: str,
    channel: str,
    message: str,
) -> bool:
    """
    Slack is a consumer platform — always blocked for PHI.
    The check catches this at layer 3 (BAA: Blocked Consumer Platform).
    """
    result = check(
        role=role,
        purpose=purpose,
        tool="post_message",
        vendor_id="slack",       # always blocked
        payload=message,
    )

    if result.blocked:
        print(f"  ✗ SLACK BLOCKED: [{result.rule}]")
        print(f"    Reason: {result.reason}")
        return False

    print(f"  ✓ SLACK ALLOWED — posting to #{channel}")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Pattern 3 — HTTP client calling the local sidecar server
# ─────────────────────────────────────────────────────────────────────────────

def check_via_http(
    role: str,
    purpose: str,
    tool: str,
    payload: str,
    patient_id: str = "",
    vendor_id: str = "",
) -> dict:
    """
    Call the guardrail server running at localhost:8100.
    Use this from non-Python services (Node.js, Go, bash scripts, etc.),
    or when you want the guardrail isolated from the main process.

    Requires:
        uvicorn guardrails.server:app --host 127.0.0.1 --port 8100
    """
    import urllib.request

    payload_body = json.dumps({
        "role": role,
        "purpose": purpose,
        "tool": tool,
        "payload": payload,
        "patient_id": patient_id,
        "vendor_id": vendor_id,
    }).encode()

    req = urllib.request.Request(
        "http://127.0.0.1:8100/check",
        data=payload_body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=2) as resp:
        return json.loads(resp.read())


# ─────────────────────────────────────────────────────────────────────────────
# Pattern 4 — decorator for any function that touches PHI
# ─────────────────────────────────────────────────────────────────────────────

def phi_guard(role: str, purpose: str, tool: str):
    """
    Decorator pattern — wraps any function that accepts a `payload` kwarg.

    @phi_guard(role="nurse", purpose="TREATMENT", tool="send_email")
    def notify_care_team(patient_id: str, payload: str) -> None:
        send_smtp(payload)
    """
    def decorator(fn):
        def wrapper(*args, payload: str = "", patient_id: str = "", **kwargs):
            result = check(
                role=role, purpose=purpose, tool=tool,
                patient_id=patient_id, payload=payload,
            )
            if result.blocked:
                raise GuardrailBlocked(result)
            return fn(*args, payload=result.redacted_payload, patient_id=patient_id, **kwargs)
        return wrapper
    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# Demo runner
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sep = "─" * 60

    print("\n" + sep)
    print("EXAMPLE 1 — Record query, nurse + RESTRICTED patient (should BLOCK at layer 5)")
    print(sep)
    result = check(
        role="nurse",
        purpose="TREATMENT",
        tool="query_patient_record",
        patient_id="P003",   # RESTRICTED — nurse cannot access psych/genetic records
    )
    if result.blocked:
        print(f"  ✗ BLOCKED at layer {result.layer}: [{result.rule}]")
        print(f"    {result.reason}")
    else:
        print("  ✓ ALLOWED (unexpected — check logic)")


    print("\n" + sep)
    print("EXAMPLE 2 — LLM call, physician + STANDARD patient (should ALLOW)")
    print(sep)
    response = call_llm_with_guard(
        role="physician",
        purpose="TREATMENT",
        patient_id="P001",                              # STANDARD
        prompt="Summarize the diabetes management plan for Jane Doe.",
    )
    print(f"  Response: {response}")

    print("\n" + sep)
    print("EXAMPLE 3 — LLM call with raw SSN in prompt (should BLOCK at PHI scan)")
    print(sep)
    try:
        call_llm_with_guard(
            role="physician",
            purpose="TREATMENT",
            patient_id="P001",
            prompt="Patient Jane Doe, SSN 123-45-6789, DOB 01/15/1960 — summarize her plan.",
        )
    except GuardrailBlocked as e:
        print(f"  ✗ BLOCKED at layer {e.result.layer}: [{e.result.rule}]")
        print(f"    PHI types: {e.result.phi_types}")
        print(f"    Risk score: {e.result.risk_score:.2f}")

    print("\n" + sep)
    print("EXAMPLE 4 — Email to change-healthcare (ALLOWED, STANDARD patient)")
    print(sep)
    send_email_with_guard(
        role="billing_staff",
        purpose="PAYMENT",
        vendor_id="change-healthcare",
        subject="Claims batch 2026-04-03",
        body="Claim batch for patient P001 processed. Code 99213.",
    )

    print("\n" + sep)
    print("EXAMPLE 5 — Slack message with patient name (should BLOCK)")
    print(sep)
    send_slack_with_guard(
        role="nurse",
        purpose="TREATMENT",
        channel="nursing-floor-4",
        message="Hey team, patient Jane Doe in 4B needs vitals check.",
    )

    print("\n" + sep)
    print("EXAMPLE 6 — Researcher queries raw record (RBAC block)")
    print(sep)
    result = check(
        role="researcher",
        purpose="RESEARCH",
        tool="query_patient_record",
        patient_id="P001",
        justification="IRB protocol 2024-001",
    )
    print(f"  blocked={result.blocked}  layer={result.layer}  rule={result.rule}")

    print()
