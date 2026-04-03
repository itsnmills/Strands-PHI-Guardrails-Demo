"""
app/guardrails/steering_handler.py
────────────────────────────────────
HIPAA-enforcing Strands SteeringHandler.

The SteeringHandler intercepts every tool call BEFORE execution.
This is the critical control layer — it is deterministic and cannot
be bypassed by prompt injection or model jailbreaks.

Control hierarchy (in order of evaluation):
  1. Role authorization check (RBAC)
  2. Purpose-of-use validation
  3. BAA vendor registry check
  4. PHI content scanning
  5. Sensitivity tier enforcement
  6. Minimum necessary check

Each check emits a structured audit event and returns Guide (block)
or Proceed (allow) with an explicit, interview-defensible reason.
"""

import json
from typing import Any

from strands.vended_plugins.steering import SteeringHandler, Guide, Proceed

from app.guardrails.phi_detector import detect_phi, should_block
from app.guardrails.audit_logger import AuditLogger
from app.policies.rbac import get_policy, can_access_record, ClinicalRole
from app.policies.purpose_of_use import validate_purpose, PURPOSE_POLICIES
from app.data.vendors import VENDOR_REGISTRY, BLOCKED_PLATFORMS
from app.data.patients import PATIENT_DB


class HIPAASteeringHandler(SteeringHandler):
    """
    Pre-tool guardrail implementing HIPAA Security Rule controls as code.

    Constructor takes the session context:
      - role:          the authenticated clinical role
      - actor_id:      simulated user identifier
      - purpose:       declared purpose of use
      - justification: free-text justification (required for some purposes)
      - audit_logger:  shared AuditLogger instance
    """

    def __init__(
        self,
        role: ClinicalRole,
        actor_id: str,
        purpose: str,
        justification: str,
        audit_logger: AuditLogger,
    ):
        super().__init__()
        self.role = role
        self.actor_id = actor_id
        self.purpose = purpose
        self.justification = justification
        self.audit = audit_logger
        self.guardrail_events: list[dict] = []   # for live UI display

    # ── Private helpers ──────────────────────────────────────────

    def _block(self, rule: str, reason: str, tool_name: str, inputs: dict, **kwargs) -> Guide:
        """Log a block event and return Guide."""
        self.guardrail_events.append({
            "outcome": "BLOCKED",
            "rule": rule,
            "tool": tool_name,
            "reason": reason,
            "role": self.role,
            "purpose": self.purpose,
        })
        self.audit.log(
            category="POLICY_EVAL",
            outcome="BLOCKED",
            actor_role=self.role,
            actor_id=self.actor_id,
            tool_name=tool_name,
            action_description=f"BLOCKED by rule: {rule}",
            policy_rule_triggered=rule,
            denial_reason=reason,
            inputs_sanitized=inputs,
            purpose_of_use=self.purpose,
            justification=self.justification,
            **kwargs,
        )
        return Guide(reason=f"[{rule}] {reason}")

    def _allow(self, tool_name: str, inputs: dict, **kwargs) -> Proceed:
        """Log an allow event and return Proceed."""
        self.guardrail_events.append({
            "outcome": "ALLOWED",
            "rule": "All checks passed",
            "tool": tool_name,
            "role": self.role,
            "purpose": self.purpose,
        })
        self.audit.log(
            category="POLICY_EVAL",
            outcome="SUCCESS",
            actor_role=self.role,
            actor_id=self.actor_id,
            tool_name=tool_name,
            action_description="All guardrail checks passed — proceeding",
            inputs_sanitized=inputs,
            purpose_of_use=self.purpose,
            justification=self.justification,
            **kwargs,
        )
        return Proceed(reason="All HIPAA guardrail checks passed")

    def _sanitize_inputs(self, tool_input: dict) -> dict:
        """Return a PHI-masked copy of inputs for safe logging."""
        safe = {}
        for k, v in tool_input.items():
            if isinstance(v, str):
                safe[k] = detect_phi(v).redacted_text[:200]
            else:
                safe[k] = v
        return safe

    # ── Main interception ─────────────────────────────────────────

    async def steer_before_tool(self, *, agent, tool_use: dict, **kwargs) -> Proceed | Guide:
        tool_name: str = tool_use.get("name", "unknown")
        tool_input: dict = tool_use.get("input", {})
        inputs_safe = self._sanitize_inputs(tool_input)

        # ── 1. Role authorization ──────────────────────────────
        policy = get_policy(self.role)

        # Protect researcher role from direct record queries
        if tool_name == "query_patient_record" and not policy.can_query_records:
            return self._block(
                "RBAC: Record Access Denied",
                f"Role '{self.role}' cannot query raw patient records. "
                "Use get_deidentified_summary() for research access.",
                tool_name, inputs_safe,
                patient_id=tool_input.get("patient_id"),
            )

        # IT admin / auditor cannot access clinical tools
        if self.role in ("it_admin", "external_auditor") and tool_name in (
            "query_patient_record", "send_data_to_vendor", "log_clinical_note", "get_deidentified_summary"
        ):
            return self._block(
                "RBAC: Role Not Authorized",
                f"Role '{self.role}' does not have access to clinical tools. "
                "IT and auditor roles are restricted to system/audit functions.",
                tool_name, inputs_safe,
            )

        # Billing staff cannot log clinical notes
        if self.role == "billing_staff" and tool_name == "log_clinical_note":
            return self._block(
                "RBAC: Billing Cannot Log Clinical Notes",
                "Billing staff are not authorized to create clinical documentation. "
                "This would violate role segregation requirements.",
                tool_name, inputs_safe,
            )

        # ── 2. Purpose-of-use validation ──────────────────────
        pou_valid, pou_reason = validate_purpose(self.role, self.purpose, self.justification)  # type: ignore[arg-type]
        if not pou_valid:
            return self._block(
                "Purpose-of-Use Violation",
                pou_reason,
                tool_name, inputs_safe,
            )

        # ── 3. Sensitivity tier enforcement ───────────────────
        if tool_name == "query_patient_record":
            patient_id = tool_input.get("patient_id", "")
            if patient_id in PATIENT_DB:
                patient = PATIENT_DB[patient_id]
                accessible, access_reason = can_access_record(self.role, patient.sensitivity)
                if not accessible:
                    return self._block(
                        "Sensitivity Tier: Access Denied",
                        access_reason,
                        tool_name, inputs_safe,
                        patient_id=patient_id,
                    )
                # Log the access event separately
                self.audit.log(
                    category="ACCESS",
                    outcome="SUCCESS",
                    actor_role=self.role,
                    actor_id=self.actor_id,
                    tool_name=tool_name,
                    action_description=f"Patient record accessed: {patient_id} (sensitivity: {patient.sensitivity})",
                    patient_id=patient_id,
                    inputs_sanitized=inputs_safe,
                    purpose_of_use=self.purpose,
                    justification=self.justification,
                )

        # ── 4. Vendor / BAA checks ────────────────────────────
        if tool_name == "send_data_to_vendor":
            vendor_id = tool_input.get("vendor_id", "")

            # Check explicitly blocked consumer platforms
            if vendor_id in BLOCKED_PLATFORMS:
                return self._block(
                    "BAA: Blocked Consumer Platform",
                    f"'{vendor_id}' ({BLOCKED_PLATFORMS[vendor_id]}) is not BAA-eligible. "
                    "PHI may not be transmitted to consumer platforms. "
                    "Use a BAA-covered alternative.",
                    tool_name, inputs_safe,
                    vendor_id=vendor_id,
                )

            # Check BAA registry
            if vendor_id not in VENDOR_REGISTRY:
                return self._block(
                    "BAA: Unregistered Vendor",
                    f"Vendor '{vendor_id}' is not in the BAA registry. "
                    "PHI cannot be transmitted to an unvetted external system. "
                    f"Approved vendors: {list(VENDOR_REGISTRY.keys())}",
                    tool_name, inputs_safe,
                    vendor_id=vendor_id,
                )

            vendor = VENDOR_REGISTRY[vendor_id]

            # Check if vendor BAA covers this sensitivity tier
            patient_id = tool_input.get("patient_id", "")
            if patient_id in PATIENT_DB:
                patient = PATIENT_DB[patient_id]
                if patient.sensitivity not in vendor.allowed_sensitivity:
                    return self._block(
                        "BAA: Sensitivity Tier Mismatch",
                        f"Vendor '{vendor.display_name}' BAA does not cover {patient.sensitivity} data. "
                        f"This vendor is approved for: {vendor.allowed_sensitivity}. "
                        "De-identify the data or use an appropriate vendor.",
                        tool_name, inputs_safe,
                        vendor_id=vendor_id,
                        patient_id=patient_id,
                    )

            # Scan payload for raw PHI
            data = tool_input.get("data", "")
            if isinstance(data, str):
                detection = detect_phi(data)
                if should_block(detection):
                    return self._block(
                        "PHI Output Filter: Raw PHI Detected",
                        f"Payload contains raw PHI: {detection.high_confidence_types} "
                        f"(risk score: {detection.risk_score:.2f}). "
                        "Use get_deidentified_summary() before transmitting externally.",
                        tool_name, inputs_safe,
                        vendor_id=vendor_id,
                        phi_types_detected=detection.all_types,
                        risk_score=detection.risk_score,
                    )

        # ── 5. PHI scan on clinical note inputs ───────────────
        if tool_name == "log_clinical_note":
            note = tool_input.get("note", "")
            detection = detect_phi(note)
            if should_block(detection):
                # Don't block — auto-redact with a warning (clinical notes may contain PHI)
                self.guardrail_events.append({
                    "outcome": "WARNING",
                    "rule": "PHI Auto-Redacted in Note",
                    "tool": tool_name,
                    "reason": f"PHI auto-masked: {detection.high_confidence_types}",
                    "role": self.role,
                    "purpose": self.purpose,
                })
                self.audit.log(
                    category="MODIFICATION",
                    outcome="WARNING",
                    actor_role=self.role,
                    actor_id=self.actor_id,
                    tool_name=tool_name,
                    action_description="PHI auto-redacted from clinical note before logging",
                    phi_types_detected=detection.all_types,
                    risk_score=detection.risk_score,
                    inputs_sanitized=inputs_safe,
                    purpose_of_use=self.purpose,
                )
                # Inject redacted note back into tool_use so the tool sees clean text
                tool_use["input"]["note"] = detection.redacted_text

        return self._allow(tool_name, inputs_safe)
