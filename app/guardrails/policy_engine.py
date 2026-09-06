"""
app/guardrails/policy_engine.py
───────────────────────────────
Deterministic HIPAA policy engine shared by the deterministic demo mode,
the policy matrix, and the test suite.

Mirrors the evaluation order of app/guardrails/steering_handler.py:
RBAC → purpose-of-use → sensitivity tier → BAA registry → PHI scan → minimum necessary.

The SteeringHandler remains the enforcement point on the live-agent path;
this module exists so policy behavior can be evaluated without an LLM,
which keeps the demo free to run and the tests free of API credentials.
"""

import re
from dataclasses import dataclass, field
from typing import Any

from app.guardrails.phi_detector import detect_phi, should_block
from app.policies.rbac import get_policy
from app.policies.purpose_of_use import PURPOSE_POLICIES
from app.data.vendors import VENDOR_REGISTRY, BLOCKED_PLATFORMS
from app.data.patients import PATIENT_DB

CONTROL_ORDER: list[tuple[str, str]] = [
    ("rbac", "RBAC — Role Authorization"),
    ("pou", "Purpose-of-Use Validation"),
    ("baa", "BAA Vendor Registry"),
    ("phi", "PHI Content Scan"),
    ("sens", "Sensitivity Tier Check"),
    ("minnec", "Minimum Necessary"),
]

CLINICAL_TOOLS = ("query_patient_record", "send_data_to_vendor", "log_clinical_note", "get_deidentified_summary")
NON_CLINICAL_ROLES = ("it_admin", "external_auditor")

_NARRATIVE_CUES = re.compile(
    r"\b(born|date\s+of\s+birth|years[-\s]old|lives?\s+on|lives?\s+in|resides?\s+at|"
    r"street|avenue|boulevard|lane)\b",
    re.IGNORECASE,
)


@dataclass
class ControlStep:
    control: str
    label: str
    status: str          # pass / skip / warn / block
    detail: str = ""


@dataclass
class PolicyResult:
    tool: str
    role: str
    purpose: str
    outcome: str                  # ALLOWED / BLOCKED
    rule: str | None = None
    reason: str | None = None
    advisory: str | None = None
    trace: dict[str, ControlStep] = field(default_factory=dict)
    phi: Any = None               # DetectionResult when a payload was scanned
    patient_id: str | None = None
    vendor_id: str | None = None

    @property
    def steps(self) -> list[ControlStep]:
        return [self.trace[cid] for cid, _ in CONTROL_ORDER]


def evaluate(
    role: str,
    purpose: str,
    justification: str,
    tool_name: str,
    tool_inputs: dict[str, Any],
) -> PolicyResult:
    policy = get_policy(role)  # type: ignore[arg-type]
    pou_policy = PURPOSE_POLICIES[purpose]
    trace: dict[str, ControlStep] = {}

    for cid, label in CONTROL_ORDER:
        trace[cid] = ControlStep(control=cid, label=label, status="skip", detail="Not applicable to this action")

    patient_id = tool_inputs.get("patient_id") or None
    patient = PATIENT_DB.get(patient_id) if patient_id else None
    vendor_id = tool_inputs.get("vendor_id") or None
    payload = tool_inputs.get("data", "") if isinstance(tool_inputs.get("data"), str) else tool_inputs.get("note", "")
    if not isinstance(payload, str):
        payload = ""

    result = PolicyResult(tool=tool_name, role=role, purpose=purpose, outcome="ALLOWED",
                          trace=trace, patient_id=patient_id, vendor_id=vendor_id)

    def finish(r: PolicyResult, status: str, ctrl: str, detail: str, rule: str, reason: str) -> PolicyResult:
        trace[ctrl] = ControlStep(control=ctrl, label=trace[ctrl].label, status=status, detail=detail)
        r.outcome = "BLOCKED"
        r.rule = rule
        r.reason = reason
        return r

    trace["rbac"] = ControlStep("rbac", trace["rbac"].label, "pass", "")
    if role in NON_CLINICAL_ROLES and tool_name in CLINICAL_TOOLS:
        trace["rbac"] = ControlStep("rbac", trace["rbac"].label, "block", f"Role '{role}' is restricted to system/audit functions")
        return finish(result, "block", "rbac", trace["rbac"].detail,
                      "RBAC: Role Not Authorized",
                      f"Role '{role}' has no clinical data access. IT and auditor roles are restricted to system/audit functions.")
    if tool_name == "query_patient_record" and not policy.can_query_records:
        trace["rbac"] = ControlStep("rbac", trace["rbac"].label, "block", f"Role '{role}' has no raw-record access")
        return finish(result, "block", "rbac", trace["rbac"].detail,
                      "RBAC: Record Access Denied",
                      f"Role '{role}' cannot query raw patient records. Use get_deidentified_summary() for research access.")
    if role == "billing_staff" and tool_name == "log_clinical_note":
        trace["rbac"] = ControlStep("rbac", trace["rbac"].label, "block", "Billing staff cannot create clinical documentation")
        return finish(result, "block", "rbac", trace["rbac"].detail,
                      "RBAC: Billing Cannot Log Clinical Notes",
                      "Billing staff are not authorized to create clinical documentation. Role segregation violation.")
    trace["rbac"].detail = f"Role '{role}' authorized for {tool_name}"

    trace["pou"] = ControlStep("pou", trace["pou"].label, "pass", "")
    if role not in pou_policy.allowed_roles:
        trace["pou"] = ControlStep("pou", trace["pou"].label, "block", f"'{purpose}' is not valid for role '{role}'")
        return finish(result, "block", "pou", trace["pou"].detail,
                      "Purpose-of-Use Violation",
                      f"Role '{role}' is not authorized to use purpose '{purpose}'. Authorized roles: {pou_policy.allowed_roles}.")
    if pou_policy.requires_justification_text and not (justification or "").strip():
        trace["pou"] = ControlStep("pou", trace["pou"].label, "block", "Written justification required and missing")
        return finish(result, "block", "pou", trace["pou"].detail,
                      "Purpose-of-Use: Missing Justification",
                      f"Purpose '{purpose}' requires a written justification before PHI can be accessed. Provide a brief explanation of why this access is needed.")
    trace["pou"].detail = (f"{purpose} valid — justification on file" if pou_policy.requires_justification_text
                           else f"{purpose} valid for role '{role}'")

    if tool_name == "query_patient_record" and patient:
        trace["sens"] = ControlStep("sens", trace["sens"].label, "pass", "")
        if patient.sensitivity == "RESTRICTED" and not policy.can_view_restricted:
            trace["sens"] = ControlStep("sens", trace["sens"].label, "block", f"{patient_id} is RESTRICTED — outside role '{role}' scope")
            return finish(result, "block", "sens", trace["sens"].detail,
                          "Sensitivity Tier: Access Denied",
                          f"Role '{role}' is not authorized to access RESTRICTED records (psychiatric, genetic). "
                          "Requires separate patient authorization under 42 CFR Part 2 / state mental health law.")
        if patient.sensitivity == "SENSITIVE" and not policy.can_view_sensitive:
            trace["sens"] = ControlStep("sens", trace["sens"].label, "block", f"{patient_id} is SENSITIVE — outside role '{role}' scope")
            return finish(result, "block", "sens", trace["sens"].detail,
                          "Sensitivity Tier: Access Denied",
                          f"Role '{role}' is not authorized to access SENSITIVE records (substance use, HIV, reproductive). "
                          "Minimum necessary access denied.")
        trace["sens"].detail = f"{patient_id} tier {patient.sensitivity} — within role '{role}' scope"

    if tool_name == "send_data_to_vendor":
        trace["baa"] = ControlStep("baa", trace["baa"].label, "pass", "")
        if vendor_id in BLOCKED_PLATFORMS:
            trace["baa"] = ControlStep("baa", trace["baa"].label, "block", f"'{vendor_id}' is a consumer platform — no BAA available")
            return finish(result, "block", "baa", trace["baa"].detail,
                          "BAA: Blocked Consumer Platform",
                          f"'{vendor_id}' ({BLOCKED_PLATFORMS[vendor_id]}) is not BAA-eligible. PHI may not be transmitted to consumer platforms. Use a BAA-covered alternative.")
        if not vendor_id or vendor_id not in VENDOR_REGISTRY:
            trace["baa"] = ControlStep("baa", trace["baa"].label, "block", f"'{vendor_id or 'unknown destination'}' not in BAA registry")
            return finish(result, "block", "baa", trace["baa"].detail,
                          "BAA: Unregistered Vendor",
                          f"Vendor '{vendor_id or 'unknown destination'}' is not in the BAA registry. PHI cannot be transmitted to an unvetted external system. "
                          f"Approved vendors: {list(VENDOR_REGISTRY.keys())}.")
        if patient and patient.sensitivity not in VENDOR_REGISTRY[vendor_id].allowed_sensitivity:
            trace["baa"] = ControlStep("baa", trace["baa"].label, "block", f"{vendor_id} BAA does not cover {patient.sensitivity}")
            return finish(result, "block", "baa", trace["baa"].detail,
                          "BAA: Sensitivity Tier Mismatch",
                          f"Vendor '{VENDOR_REGISTRY[vendor_id].display_name}' BAA does not cover {patient.sensitivity} data "
                          f"(approved for: {VENDOR_REGISTRY[vendor_id].allowed_sensitivity}). De-identify the data or use an appropriate vendor.")
        trace["baa"].detail = f"{vendor_id} BAA verified" + (f" — covers {patient.sensitivity}" if patient else "")

        detection = detect_phi(payload)
        result.phi = detection
        if should_block(detection):
            trace["phi"] = ControlStep("phi", trace["phi"].label, "block",
                                       f"Raw PHI in payload: {', '.join(detection.high_confidence_types)} — risk {detection.risk_score:.2f}")
            return finish(result, "block", "phi", trace["phi"].detail,
                          "PHI Output Filter: Raw PHI Detected",
                          f"Payload contains raw PHI: {detection.high_confidence_types} (risk score: {detection.risk_score:.2f}). "
                          "Use get_deidentified_summary() before transmitting externally.")
        if detection.phi_found:
            trace["phi"] = ControlStep("phi", trace["phi"].label, "warn",
                                       f"Low-confidence pattern noted ({', '.join(detection.all_types)}) — below block threshold")
            if _NARRATIVE_CUES.search(payload):
                result.advisory = ("Payload also contains narrative PHI cues (date of birth, address) that regex cannot confirm. "
                                   "In production an NER layer (AWS Comprehend Medical, Presidio) would flag this payload.")
        elif _NARRATIVE_CUES.search(payload):
            trace["phi"] = ControlStep("phi", trace["phi"].label, "warn", "Narrative birth/address cues detected — no regex match")
            result.advisory = ("Payload contains narrative PHI cues that regex cannot confirm. "
                               "In production an NER layer (AWS Comprehend Medical, Presidio) would flag this payload.")
        else:
            trace["phi"] = ControlStep("phi", trace["phi"].label, "pass", "Payload clean — no PHI patterns matched")
    elif tool_name == "log_clinical_note":
        detection = detect_phi(payload)
        result.phi = detection
        if detection.phi_found:
            trace["phi"] = ControlStep("phi", trace["phi"].label, "warn",
                                       f"PHI auto-redacted before logging ({', '.join(detection.all_types)})")
        else:
            trace["phi"] = ControlStep("phi", trace["phi"].label, "pass", "Note clean — no PHI patterns")

    trace["minnec"] = ControlStep("minnec", trace["minnec"].label, "pass", "")
    if tool_name == "query_patient_record":
        trace["minnec"].detail = f"Scope: 1 record — within role budget ({policy.max_records_per_query} per query)"
    elif tool_name == "send_data_to_vendor":
        trace["minnec"].detail = "Payload reviewed for minimum-necessary disclosure"
    elif tool_name == "get_deidentified_summary":
        trace["minnec"].detail = "De-identified scope — direct identifiers removed"
    else:
        trace["minnec"].detail = "Read-only lookup — no PHI disclosed"

    return result
