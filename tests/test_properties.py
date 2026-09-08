"""
tests/test_properties.py
────────────────────────
Property-based tests (Hypothesis) for the deterministic policy engine.

No LLM is called — properties run directly against app.guardrails.policy_engine,
which is pure and dependency-free. Run with: pytest tests/test_properties.py -v

Where the eval suite (tests/test_evals.py) checks known scenarios, these tests
assert the engine's SECURITY INVARIANTS hold for arbitrary inputs drawn from
the real registries (roles, purposes, patients, vendors) plus adversarial
strings. Each @given test names the invariant it protects.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hypothesis import given, settings
from hypothesis import strategies as st

from app.guardrails.policy_engine import evaluate, CONTROL_ORDER, CLINICAL_TOOLS
from app.guardrails.phi_detector import detect_phi, should_block
from app.policies.rbac import get_policy, ROLE_POLICIES
from app.policies.purpose_of_use import PURPOSE_POLICIES
from app.data.patients import PATIENT_DB
from app.data.vendors import VENDOR_REGISTRY, BLOCKED_PLATFORMS


# ── Strategies built from the ACTUAL registries ───────────────
TOOLS = [
    "query_patient_record",
    "send_data_to_vendor",
    "log_clinical_note",
    "get_deidentified_summary",
    "check_vendor_baa_status",
]

CLINICAL_TOOL_LIST = list(CLINICAL_TOOLS)  # the four clinical tools

roles = st.sampled_from(sorted(ROLE_POLICIES))
purposes = st.sampled_from(sorted(PURPOSE_POLICIES))
tools = st.sampled_from(TOOLS)
patient_ids = st.none() | st.sampled_from(sorted(PATIENT_DB))
vendor_ids = st.none() | st.sampled_from(
    sorted(VENDOR_REGISTRY)
    + sorted(BLOCKED_PLATFORMS)
    + ["AWS-Bedrock", "aws-bedrock ", "aws-bedrock.evil.com", "slack-workspace", ""]
)
justifications = st.sampled_from(
    ["", " ", "IRB #2026-0042", "Treatment follow-up", "Claims batch Q1"]
) | st.text(max_size=50)
payloads = st.sampled_from(
    [
        "Vitals stable. Continue current treatment plan.",
        "Patient reports no pain today. Labs pending.",
        "SSN 123-45-6789",
        "DOB 03/15/1985",
        "call 555-867-5309",
        "jane.doe@hospital.org",
        "42 Elm Street",
        "",
    ]
) | st.text(max_size=80)


def run_engine(role, purpose, justification, tool, patient_id, vendor_id, payload):
    """Evaluate one action, routing the payload to the key the engine reads."""
    tool_inputs = {"patient_id": patient_id, "vendor_id": vendor_id}
    if tool == "send_data_to_vendor":
        tool_inputs["data"] = payload
    elif tool == "log_clinical_note":
        tool_inputs["note"] = payload
    return evaluate(role, purpose, justification, tool, tool_inputs)


# ── Invariant 1: determinism ──────────────────────────────────
@given(roles, purposes, justifications, tools, patient_ids, vendor_ids, payloads)
@settings(max_examples=200, deadline=None)
def test_determinism(role, purpose, justification, tool, patient_id, vendor_id, payload):
    """DETERMINISM: two identical evaluate() calls produce identical outcome, rule, and reason."""
    first = run_engine(role, purpose, justification, tool, patient_id, vendor_id, payload)
    second = run_engine(role, purpose, justification, tool, patient_id, vendor_id, payload)
    assert (first.outcome, first.rule, first.reason) == (second.outcome, second.rule, second.reason), (
        f"Nondeterministic decision for role={role!r} purpose={purpose!r} tool={tool!r} "
        f"patient_id={patient_id!r} vendor_id={vendor_id!r}: "
        f"{(first.outcome, first.rule, first.reason)!r} != {(second.outcome, second.rule, second.reason)!r}"
    )


# ── Invariant 2: trace integrity ──────────────────────────────
@given(roles, purposes, justifications, tools, patient_ids, vendor_ids, payloads)
@settings(max_examples=200, deadline=None)
def test_trace_integrity(role, purpose, justification, tool, patient_id, vendor_id, payload):
    """TRACE INTEGRITY: trace contains every CONTROL_ORDER key; steps come back in
    CONTROL_ORDER; at most one step is 'block'; any step after a block is 'skip'."""
    result = run_engine(role, purpose, justification, tool, patient_id, vendor_id, payload)
    order = [cid for cid, _ in CONTROL_ORDER]

    assert set(order).issubset(result.trace), f"trace missing controls: {set(order) - set(result.trace)}"
    assert [s.control for s in result.steps] == order, "steps not returned in CONTROL_ORDER"

    blocked_positions = [i for i, s in enumerate(result.steps) if s.status == "block"]
    assert len(blocked_positions) <= 1, f"multiple blocking controls: {[result.steps[i].control for i in blocked_positions]}"
    if blocked_positions:
        first_block = blocked_positions[0]
        for later in result.steps[first_block + 1:]:
            assert later.status == "skip", (
                f"control '{later.control}' ran ({later.status}) after blocking control "
                f"'{result.steps[first_block].control}'"
            )


# ── Invariant 3: blocked sanity ───────────────────────────────
@given(roles, purposes, justifications, tools, patient_ids, vendor_ids, payloads)
@settings(max_examples=200, deadline=None)
def test_blocked_sanity(role, purpose, justification, tool, patient_id, vendor_id, payload):
    """BLOCKED SANITY: outcome 'BLOCKED' ⇒ non-empty rule and reason strings;
    outcome 'ALLOWED' ⇒ rule is None."""
    result = run_engine(role, purpose, justification, tool, patient_id, vendor_id, payload)
    assert result.outcome in ("ALLOWED", "BLOCKED"), f"unknown outcome {result.outcome!r}"
    if result.outcome == "BLOCKED":
        assert isinstance(result.rule, str) and result.rule, f"empty rule on BLOCKED: {result.rule!r}"
        assert isinstance(result.reason, str) and result.reason, f"empty reason on BLOCKED: {result.reason!r}"
    else:
        assert result.rule is None, f"ALLOWED carried a rule: {result.rule!r}"


# ── Invariant 4: unauthorized purpose always blocks ───────────
@given(roles, purposes, justifications, tools, patient_ids, vendor_ids, payloads)
@settings(max_examples=200, deadline=None)
def test_unauthorized_purpose_always_blocks(role, purpose, justification, tool, patient_id, vendor_id, payload):
    """UNAUTHORIZED PURPOSE ALWAYS BLOCKS: role not in PURPOSE_POLICIES[purpose].allowed_roles
    ⇒ outcome 'BLOCKED', regardless of tool or inputs."""
    if role not in PURPOSE_POLICIES[purpose].allowed_roles:
        result = run_engine(role, purpose, justification, tool, patient_id, vendor_id, payload)
        assert result.outcome == "BLOCKED", (
            f"Role '{role}' is not authorized for purpose '{purpose}' "
            f"(allowed: {PURPOSE_POLICIES[purpose].allowed_roles}) but outcome was {result.outcome!r}"
        )


# ── Invariant 5: missing justification always blocks ──────────
@given(roles, purposes, justifications, tools, patient_ids, vendor_ids, payloads)
@settings(max_examples=200, deadline=None)
def test_missing_justification_always_blocks(role, purpose, justification, tool, patient_id, vendor_id, payload):
    """MISSING JUSTIFICATION ALWAYS BLOCKS: purposes that require written justification
    block when justification.strip() is empty."""
    if PURPOSE_POLICIES[purpose].requires_justification_text and justification.strip() == "":
        result = run_engine(role, purpose, justification, tool, patient_id, vendor_id, payload)
        assert result.outcome == "BLOCKED", (
            f"Purpose '{purpose}' requires justification but empty justification "
            f"({justification!r}) produced outcome {result.outcome!r}"
        )


# ── Invariant 6: blocked platforms never allow ────────────────
@given(roles, purposes, justifications, tools, patient_ids, vendor_ids, payloads)
@settings(max_examples=200, deadline=None)
def test_blocked_platforms_never_allow(role, purpose, justification, tool, patient_id, vendor_id, payload):
    """BLOCKED PLATFORMS NEVER ALLOW: send_data_to_vendor to a BLOCKED_PLATFORMS key
    ⇒ outcome 'BLOCKED'."""
    if tool == "send_data_to_vendor" and vendor_id in BLOCKED_PLATFORMS:
        result = run_engine(role, purpose, justification, tool, patient_id, vendor_id, payload)
        assert result.outcome == "BLOCKED", (
            f"Blocked consumer platform '{vendor_id}' was not stopped: outcome {result.outcome!r}"
        )


# ── Invariant 7: unregistered vendor never allows ─────────────
@given(roles, purposes, justifications, tools, patient_ids, vendor_ids, payloads)
@settings(max_examples=200, deadline=None)
def test_unregistered_vendor_never_allows(role, purpose, justification, tool, patient_id, vendor_id, payload):
    """UNREGISTERED VENDOR NEVER ALLOWS: send_data_to_vendor with vendor_id absent from
    VENDOR_REGISTRY (None counts as unregistered) ⇒ outcome 'BLOCKED'."""
    if tool == "send_data_to_vendor" and (vendor_id is None or vendor_id not in VENDOR_REGISTRY):
        result = run_engine(role, purpose, justification, tool, patient_id, vendor_id, payload)
        assert result.outcome == "BLOCKED", (
            f"Unregistered vendor {vendor_id!r} was not stopped: outcome {result.outcome!r}"
        )


# ── Invariant 8: no raw PHI egress ────────────────────────────
@given(roles, purposes, justifications, tools, patient_ids, vendor_ids, payloads)
@settings(max_examples=200, deadline=None)
def test_no_raw_phi_egress(role, purpose, justification, tool, patient_id, vendor_id, payload):
    """NO RAW PHI EGRESS: send_data_to_vendor with a payload that should_block(detect_phi())
    flags ⇒ outcome 'BLOCKED' (BAA or PHI filter stops it — never ALLOWED)."""
    if tool == "send_data_to_vendor" and should_block(detect_phi(payload)):
        result = run_engine(role, purpose, justification, tool, patient_id, vendor_id, payload)
        assert result.outcome == "BLOCKED", (
            f"Raw PHI payload {payload!r} was sent to {vendor_id!r}: outcome {result.outcome!r}"
        )


# ── Invariant 9: allowed-send cleanliness ─────────────────────
@given(roles, purposes, justifications, tools, patient_ids, vendor_ids, payloads)
@settings(max_examples=200, deadline=None)
def test_allowed_send_cleanliness(role, purpose, justification, tool, patient_id, vendor_id, payload):
    """ALLOWED-SEND CLEANLINESS: an ALLOWED send_data_to_vendor implies the vendor is
    registered, not blocked, the patient tier (if any) is covered by the vendor's BAA,
    and the payload contains no blockable PHI."""
    if tool == "send_data_to_vendor" and run_engine(
        role, purpose, justification, tool, patient_id, vendor_id, payload
    ).outcome == "ALLOWED":
        assert vendor_id is not None and vendor_id in VENDOR_REGISTRY, (
            f"ALLOWED send to unregistered vendor {vendor_id!r}"
        )
        assert vendor_id not in BLOCKED_PLATFORMS, f"ALLOWED send to blocked platform {vendor_id!r}"
        patient = PATIENT_DB.get(patient_id) if patient_id else None
        assert patient is None or patient.sensitivity in VENDOR_REGISTRY[vendor_id].allowed_sensitivity, (
            f"ALLOWED send of {patient.sensitivity if patient else None} data to {vendor_id!r} "
            f"(covers {VENDOR_REGISTRY[vendor_id].allowed_sensitivity})"
        )
        assert not should_block(detect_phi(payload)), f"ALLOWED send of PHI-bearing payload {payload!r}"


# ── Invariant 10: allowed-query tier respect ──────────────────
@given(roles, purposes, justifications, tools, patient_ids, vendor_ids, payloads)
@settings(max_examples=200, deadline=None)
def test_allowed_query_tier_respect(role, purpose, justification, tool, patient_id, vendor_id, payload):
    """ALLOWED-QUERY TIER RESPECT: an ALLOWED query_patient_record implies the role may
    query records, and — for a known patient — the record's tier is within the role's
    scope (STANDARD freely; SENSITIVE/RESTRICTED only with the matching capability)."""
    result = run_engine(role, purpose, justification, tool, patient_id, vendor_id, payload)
    if tool == "query_patient_record" and result.outcome == "ALLOWED":
        policy = get_policy(role)
        assert policy.can_query_records is True, (
            f"ALLOWED query for role '{role}' without can_query_records"
        )
        patient = PATIENT_DB.get(patient_id) if patient_id else None
        if patient is not None:
            tier_ok = (
                patient.sensitivity == "STANDARD"
                or (patient.sensitivity == "SENSITIVE" and policy.can_view_sensitive)
                or (patient.sensitivity == "RESTRICTED" and policy.can_view_restricted)
            )
            assert tier_ok, (
                f"ALLOWED query of {patient.sensitivity} record {patient_id} by role '{role}' "
                f"(can_view_sensitive={policy.can_view_sensitive}, "
                f"can_view_restricted={policy.can_view_restricted})"
            )


# ── Invariant 11: RBAC zero-PHI roles ─────────────────────────
@given(roles, purposes, justifications, tools, patient_ids, vendor_ids, payloads)
@settings(max_examples=200, deadline=None)
def test_rbac_zero_phi_roles(role, purpose, justification, tool, patient_id, vendor_id, payload):
    """RBAC ZERO-PHI ROLES: it_admin and external_auditor are blocked from all four
    clinical tools, for every purpose and input combination."""
    if role in ("it_admin", "external_auditor") and tool in CLINICAL_TOOL_LIST:
        result = run_engine(role, purpose, justification, tool, patient_id, vendor_id, payload)
        assert result.outcome == "BLOCKED", (
            f"Zero-PHI role '{role}' reached clinical tool '{tool}': outcome {result.outcome!r}"
        )


# ── Invariant 12: billing segregation ─────────────────────────
@given(roles, purposes, justifications, tools, patient_ids, vendor_ids, payloads)
@settings(max_examples=200, deadline=None)
def test_billing_segregation(role, purpose, justification, tool, patient_id, vendor_id, payload):
    """BILLING SEGREGATION: billing_staff can never create clinical documentation —
    log_clinical_note is always blocked for that role."""
    if role == "billing_staff" and tool == "log_clinical_note":
        result = run_engine(role, purpose, justification, tool, patient_id, vendor_id, payload)
        assert result.outcome == "BLOCKED", (
            f"billing_staff logged a clinical note: outcome {result.outcome!r}"
        )
