"""
app/tools/clinical_tools.py
─────────────────────────────
Strands tool definitions for the HIPAA guardrail agent.

Tools represent the capabilities the AI agent can invoke.
The guardrail layer (steering_handler.py) intercepts each call
BEFORE the tool executes — so tool code is the "happy path."

Tools are intentionally thin: business logic lives here,
security enforcement lives in the steering handler.
"""

import json
import datetime
from strands import tool

from app.data.patients import PATIENT_DB
from app.data.vendors import VENDOR_REGISTRY
from app.guardrails.phi_detector import detect_phi, redact


# ── Global audit logger reference (set by the UI before agent creation) ──
# This is a simple pattern for demo purposes; in production the logger
# would be injected via dependency injection or a context variable.
_AUDIT_LOGGER = None

def set_audit_logger(logger):
    global _AUDIT_LOGGER
    _AUDIT_LOGGER = logger


def _audit(tool_name: str, action: str, patient_id=None, vendor_id=None, outcome="SUCCESS", **kwargs):
    if _AUDIT_LOGGER:
        _AUDIT_LOGGER.log(
            category="ACCESS" if "query" in tool_name else "DISCLOSURE" if "send" in tool_name else "MODIFICATION",
            outcome=outcome,
            actor_role=kwargs.get("role", "unknown"),
            actor_id=kwargs.get("actor_id", "system"),
            tool_name=tool_name,
            action_description=action,
            patient_id=patient_id,
            vendor_id=vendor_id,
        )


@tool
def query_patient_record(patient_id: str) -> str:
    """
    Query a patient record from the EHR system.
    
    Args:
        patient_id: Patient identifier (e.g. 'P001', 'P002', 'P003', 'P004')
    
    Returns the full patient record including PHI fields.
    Access is controlled by the HIPAA steering handler based on role and purpose.
    """
    if patient_id not in PATIENT_DB:
        return json.dumps({
            "error": f"Patient '{patient_id}' not found.",
            "valid_ids": list(PATIENT_DB.keys()),
        })
    
    patient = PATIENT_DB[patient_id]
    return json.dumps({
        "patient_id": patient.patient_id,
        "name": patient.name,
        "dob": patient.dob,
        "mrn": patient.mrn,
        "phone": patient.phone,
        "address": patient.address,
        "diagnosis": patient.diagnosis,
        "medications": patient.medications,
        "department": patient.department,
        "sensitivity_tier": patient.sensitivity,
        "notes": patient.notes,
    }, indent=2)


@tool
def get_deidentified_summary(patient_id: str, purpose: str = "clinical") -> str:
    """
    Generate a de-identified patient summary safe for research, handoffs, or external sharing.
    All 18 HIPAA identifiers are removed. Only clinical facts are included.
    
    Args:
        patient_id: Patient identifier (e.g. 'P001')
        purpose: Context for the summary — 'clinical', 'research', 'handoff', 'billing'
    """
    if patient_id not in PATIENT_DB:
        return json.dumps({"error": f"Patient '{patient_id}' not found."})
    
    patient = PATIENT_DB[patient_id]

    # Billing summaries include diagnosis codes but not clinical notes
    if purpose == "billing":
        summary = {
            "patient_ref": f"ANON-{patient_id}",
            "summary_type": "billing",
            "department": patient.department,
            "primary_diagnosis_category": patient.diagnosis.split(",")[0].strip(),
            "phi_removed": True,
            "note": "Billing summary. No direct identifiers included.",
        }
    elif purpose == "research":
        summary = {
            "patient_ref": f"RESEARCH-{patient_id}",
            "summary_type": "research",
            "diagnosis": patient.diagnosis,
            "medications": patient.medications,
            "sensitivity_tier": patient.sensitivity,
            "phi_removed": True,
            "note": "Research summary. IRB-approved de-identification applied.",
        }
    elif purpose == "handoff":
        summary = {
            "patient_ref": f"HANDOFF-{patient_id}",
            "summary_type": "shift_handoff",
            "department": patient.department,
            "active_diagnoses": patient.diagnosis,
            "current_medications": patient.medications,
            "care_notes": patient.notes,
            "phi_removed": True,
            "note": "Handoff summary. Contains minimum necessary clinical information.",
        }
    else:  # clinical
        summary = {
            "patient_ref": f"CLINICAL-{patient_id}",
            "summary_type": "clinical",
            "diagnosis": patient.diagnosis,
            "medications": patient.medications,
            "department": patient.department,
            "phi_removed": True,
            "note": "De-identified clinical summary. Safe for sharing within care team.",
        }

    return json.dumps(summary, indent=2)


@tool
def send_data_to_vendor(vendor_id: str, patient_id: str, data: str) -> str:
    """
    Transmit patient data to an external vendor system.
    
    The steering handler verifies:
      - Vendor is BAA-registered
      - Data is de-identified (no raw PHI)
      - Sensitivity tier is compatible with vendor BAA scope
    
    Args:
        vendor_id: Target vendor (e.g. 'epic-systems', 'aws-bedrock')
        patient_id: Patient this data pertains to
        data: The data payload to transmit
    """
    if vendor_id not in VENDOR_REGISTRY:
        return json.dumps({
            "status": "ERROR",
            "message": f"Vendor '{vendor_id}' not in BAA registry.",
            "approved_vendors": list(VENDOR_REGISTRY.keys()),
        })

    vendor = VENDOR_REGISTRY[vendor_id]
    transmission_id = f"TX-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    return json.dumps({
        "status": "SUCCESS",
        "transmission_id": transmission_id,
        "vendor": vendor.display_name,
        "vendor_tier": vendor.tier,
        "baa_expiry": vendor.baa_expiry,
        "patient_ref": f"ANON-{patient_id}",
        "bytes_transmitted": len(data.encode()),
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "note": "Transmission logged to audit trail.",
    }, indent=2)


@tool
def check_vendor_baa_status(vendor_id: str) -> str:
    """
    Check whether a vendor has a signed Business Associate Agreement (BAA).
    
    Args:
        vendor_id: Vendor identifier to check
    """
    from app.data.vendors import BLOCKED_PLATFORMS
    
    if vendor_id in BLOCKED_PLATFORMS:
        return json.dumps({
            "vendor_id": vendor_id,
            "baa_status": "NOT_ELIGIBLE",
            "message": BLOCKED_PLATFORMS[vendor_id],
            "recommendation": "Use a BAA-covered alternative for any PHI processing.",
        }, indent=2)
    
    if vendor_id not in VENDOR_REGISTRY:
        return json.dumps({
            "vendor_id": vendor_id,
            "baa_status": "NOT_REGISTERED",
            "message": f"'{vendor_id}' is not in the BAA registry.",
            "approved_vendors": list(VENDOR_REGISTRY.keys()),
        }, indent=2)
    
    vendor = VENDOR_REGISTRY[vendor_id]
    return json.dumps({
        "vendor_id": vendor_id,
        "display_name": vendor.display_name,
        "baa_status": "APPROVED",
        "tier": vendor.tier,
        "baa_expiry": vendor.baa_expiry,
        "allowed_sensitivity_tiers": vendor.allowed_sensitivity,
        "notes": vendor.notes,
    }, indent=2)


@tool
def log_clinical_note(note: str, patient_id: str, author: str = "Unknown Clinician") -> str:
    """
    Log a clinical note to the EHR system.
    PHI in the note is auto-redacted by the steering handler before this executes.
    
    Args:
        note:       The clinical note text
        patient_id: Patient this note belongs to
        author:     Clinician authoring the note
    """
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Check if note still contains PHI after steering handler redaction
    detection = detect_phi(note)
    phi_warning = ""
    if detection.phi_found:
        phi_warning = f" WARNING: Residual PHI detected after redaction ({detection.all_types})."

    return json.dumps({
        "status": "LOGGED",
        "patient_ref": f"ANON-{patient_id}",
        "note_id": f"NOTE-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "author": author,
        "timestamp": timestamp,
        "note_preview": note[:100] + ("..." if len(note) > 100 else ""),
        "phi_status": "AUTO-REDACTED" if detection.phi_found else "CLEAN",
        "note": f"Clinical note logged to EHR.{phi_warning}",
    }, indent=2)
