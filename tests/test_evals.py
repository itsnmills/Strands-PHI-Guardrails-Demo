"""
tests/test_evals.py
────────────────────
Pytest runner for guardrail eval cases.

No LLM is called — tests run directly against the policy engine.
Run with: pytest tests/test_evals.py -v

These tests verify that the HIPAA guardrail logic produces correct
BLOCKED/ALLOWED decisions for known scenarios. They can run in CI
with no API credentials.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from app.evals.eval_cases import EVAL_CASES, EvalCase
from app.data.patients import PATIENT_DB
from app.data.vendors import VENDOR_REGISTRY, BLOCKED_PLATFORMS
from app.policies.rbac import get_policy, can_access_record
from app.policies.purpose_of_use import validate_purpose
from app.guardrails.phi_detector import detect_phi, should_block


def evaluate_case(case: EvalCase) -> tuple[str, str | None]:
    """
    Simulate the steering handler's decision tree without instantiating the full handler.
    Returns (actual_outcome, actual_rule).
    """
    actual_outcome = "ALLOWED"
    actual_rule = None

    tool = case.tool_name
    inputs = case.tool_inputs
    role = case.role
    purpose = case.purpose
    justification = case.justification

    policy = get_policy(role)

    # ── Role/tool authorization checks ────────────────────────
    if tool in ("query_patient_record", "log_clinical_note", "send_data_to_vendor", "get_deidentified_summary"):
        if role in ("it_admin", "external_auditor") and tool != "check_vendor_baa_status":
            return "BLOCKED", "RBAC: Role Not Authorized"

    if tool == "query_patient_record":
        if not policy.can_query_records:
            return "BLOCKED", "RBAC: Record Access Denied"

        pou_valid, _ = validate_purpose(role, purpose, justification)
        if not pou_valid:
            return "BLOCKED", "Purpose-of-Use Violation"

        patient_id = inputs.get("patient_id", "")
        if patient_id in PATIENT_DB:
            patient = PATIENT_DB[patient_id]
            accessible, _ = can_access_record(role, patient.sensitivity)
            if not accessible:
                return "BLOCKED", "Sensitivity Tier: Access Denied"

    elif tool == "log_clinical_note":
        if role == "billing_staff":
            return "BLOCKED", "RBAC: Billing Cannot Log Clinical Notes"

    elif tool == "send_data_to_vendor":
        vendor_id = inputs.get("vendor_id", "")
        if vendor_id in BLOCKED_PLATFORMS:
            return "BLOCKED", "BAA: Blocked Consumer Platform"
        if vendor_id not in VENDOR_REGISTRY:
            return "BLOCKED", "BAA: Unregistered Vendor"

        vendor = VENDOR_REGISTRY[vendor_id]
        patient_id = inputs.get("patient_id", "")
        if patient_id in PATIENT_DB:
            patient = PATIENT_DB[patient_id]
            if patient.sensitivity not in vendor.allowed_sensitivity:
                return "BLOCKED", "BAA: Sensitivity Tier Mismatch"

        data = inputs.get("data", "")
        detection = detect_phi(data)
        if should_block(detection):
            return "BLOCKED", "PHI Output Filter: Raw PHI Detected"

    elif tool == "get_deidentified_summary":
        pou_valid, _ = validate_purpose(role, purpose, justification)
        if not pou_valid:
            return "BLOCKED", "Purpose-of-Use Violation"

    return actual_outcome, actual_rule


# ── Generate parametrized test cases ──────────────────────────
non_edge_cases = [c for c in EVAL_CASES if not c.edge_case]
edge_cases = [c for c in EVAL_CASES if c.edge_case]


@pytest.mark.parametrize("case", non_edge_cases, ids=[c.case_id for c in non_edge_cases])
def test_guardrail_policy(case: EvalCase):
    """Standard policy eval cases — must pass."""
    actual_outcome, actual_rule = evaluate_case(case)
    
    assert actual_outcome == case.expected_outcome, (
        f"\n[{case.case_id}] {case.description}\n"
        f"Expected: {case.expected_outcome} | Got: {actual_outcome}\n"
        f"Expected rule: {case.expected_rule} | Got rule: {actual_rule}\n"
        f"Rationale: {case.rationale}"
    )
    
    if case.expected_outcome == "BLOCKED" and case.expected_rule:
        assert actual_rule == case.expected_rule, (
            f"\n[{case.case_id}] Wrong rule triggered.\n"
            f"Expected: {case.expected_rule}\n"
            f"Got: {actual_rule}"
        )


@pytest.mark.parametrize("case", edge_cases, ids=[c.case_id for c in edge_cases])
def test_edge_cases_documented(case: EvalCase):
    """
    Edge cases — these test known limitations.
    They verify the DOCUMENTED behavior (including known gaps).
    Passing means: the system behaves as expected AND the gap is acknowledged.
    """
    actual_outcome, _ = evaluate_case(case)
    
    # Edge cases should produce the documented outcome (even if it's a gap)
    assert actual_outcome == case.expected_outcome, (
        f"\n[{case.case_id}] EDGE CASE behavior changed unexpectedly.\n"
        f"Expected: {case.expected_outcome} | Got: {actual_outcome}\n"
        f"This edge case documents: {case.rationale}"
    )


if __name__ == "__main__":
    print("Running guardrail policy eval suite...\n")
    passed = 0
    failed = 0
    for case in EVAL_CASES:
        outcome, rule = evaluate_case(case)
        ok = outcome == case.expected_outcome
        tag = "✅ PASS" if ok else "❌ FAIL"
        edge = " [EDGE]" if case.edge_case else ""
        print(f"{tag} {case.case_id}{edge}: {case.description}")
        if not ok:
            print(f"       Expected: {case.expected_outcome} | Got: {outcome}")
            failed += 1
        else:
            passed += 1
    print(f"\n{passed}/{passed+failed} cases passed.")
