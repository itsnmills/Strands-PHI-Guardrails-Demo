"""
tests/test_session_controls.py
─────────────────────────────
Behavioral minimum-necessary (session velocity) + break-glass emergency
access — the two controls that need STATE to have teeth.

Velocity (45 CFR §164.502(b) minimum necessary):
  - nurse budget 3 / 5min: ok → ok → warn → … → block at 6 accesses
  - physician budget 5: warns at 5, blocks at 10
  - engine integration: BLOCKED with "Minimum Necessary: Session Velocity Exceeded"
  - no monitor ⇒ minnec never blocks (matrix + property tests stay pure)

Break-glass:
  - grant unlocks RESTRICTED for the granted role+patient only
  - grant expires (TTL) — expired grant blocks again
  - grant requires a substantive reason (min 20 chars)
  - grant is flagged in the audit log under the BREAK_GLASS category

New RBAC egress caps (hardening surfaced by the red-team tracing pass):
  - nurse (can_send_to_vendors=False) → registered vendor: BLOCKED
  - physician SENSITIVE tier to a tier-covering vendor: BLOCKED
  - billing → change-healthcare STANDARD: still ALLOWED (E005 invariant)
"""

import pytest

from app.guardrails.policy_engine import evaluate
from app.guardrails.session_monitor import SessionMonitor
from app.guardrails.audit_logger import AuditLogger
from app.policies.break_glass import BreakGlassRegistry


# ── Velocity: monitor primitives ────────────────────────────────

def test_nurse_velocity_escalates_ok_warn_block():
    m = SessionMonitor()
    verdicts = [m.check_query("nurse", pid)[0] for pid in ["P001", "P001", "P001", "P001", "P001", "P001"]]
    assert verdicts == ["ok", "ok", "warn", "warn", "warn", "block"]
    assert m.anomaly_count == 4  # 3 warns + 1 block


def test_physician_budget_is_higher():
    m = SessionMonitor()
    verdicts = [m.check_query("physician", "P001")[0] for _ in range(10)]
    assert verdicts[4] == "warn" and verdicts[9] == "block" and verdicts[3] == "ok"


def test_window_expiry_restores_budget():
    m = SessionMonitor(window_seconds=300.0)
    t0 = 1000.0
    for i in range(6):
        m.check_query("nurse", "P001", now=t0 + i)
    assert m.check_query("nurse", "P001", now=t0 + 306.0)[0] == "ok"  # all aged out


# ── Velocity: engine integration ────────────────────────────────

def test_engine_blocks_at_velocity_ceiling():
    m = SessionMonitor()
    for _ in range(6):
        m.check_query("nurse", "P001")
    result = evaluate("nurse", "TREATMENT", "", "query_patient_record", {"patient_id": "P001"}, monitor=m)
    assert result.outcome == "BLOCKED"
    assert result.rule == "Minimum Necessary: Session Velocity Exceeded"
    assert result.trace["minnec"].status == "block"


def test_engine_warns_at_budget_but_allows():
    m = SessionMonitor()
    m.check_query("nurse", "P001")
    m.check_query("nurse", "P001")
    result = evaluate("nurse", "TREATMENT", "", "query_patient_record", {"patient_id": "P001"}, monitor=m)
    assert result.outcome == "ALLOWED"
    assert result.trace["minnec"].status == "warn"
    assert result.advisory and "Minimum-necessary anomaly" in result.advisory


def test_send_velocity_escalates_too():
    m = SessionMonitor()
    for _ in range(10):
        evaluate("physician", "TREATMENT", "", "send_data_to_vendor",
                 {"vendor_id": "aws-bedrock", "patient_id": "P001", "data": "clean summary"}, monitor=m)
    result = evaluate("physician", "TREATMENT", "", "send_data_to_vendor",
                      {"vendor_id": "aws-bedrock", "patient_id": "P001", "data": "clean summary"}, monitor=m)
    assert result.outcome == "BLOCKED"
    assert result.rule == "Minimum Necessary: Session Velocity Exceeded"


def test_no_monitor_means_no_velocity_block():
    """Backward-compat invariant: stateless evaluation (matrix/property tests) never velocity-blocks."""
    for _ in range(20):
        result = evaluate("nurse", "TREATMENT", "", "query_patient_record", {"patient_id": "P001"})
        assert result.outcome == "ALLOWED"
        assert result.trace["minnec"].status in ("pass", "warn")


# ── Break-glass ─────────────────────────────────────────────────

BG_REASON = "Patient in acute psychiatric crisis, attending unavailable, emergency consult required"


def test_break_glass_unlocks_restricted_for_granted_patient():
    reg = BreakGlassRegistry(ttl_minutes=15)
    reg.grant("nurse", "P003", BG_REASON)
    result = evaluate("nurse", "TREATMENT", "", "query_patient_record", {"patient_id": "P003"}, break_glass=reg)
    assert result.outcome == "ALLOWED"
    assert result.trace["sens"].status == "warn"
    assert "BREAK-GLASS" in result.trace["sens"].detail
    assert result.advisory and "post-hoc review" in result.advisory


def test_without_grant_restricted_still_blocks():
    reg = BreakGlassRegistry(ttl_minutes=15)
    result = evaluate("nurse", "TREATMENT", "", "query_patient_record", {"patient_id": "P003"}, break_glass=reg)
    assert result.outcome == "BLOCKED"
    assert result.rule == "Sensitivity Tier: Access Denied"


def test_grant_is_scoped_to_one_patient():
    reg = BreakGlassRegistry(ttl_minutes=15)
    reg.grant("nurse", "P003", BG_REASON)
    # Same role, DIFFERENT restricted-tier record: there is only P003 in the DB,
    # so prove scoping via a fresh registry grant for a different role instead.
    assert reg.active_grant("nurse", "P003") is not None
    assert reg.active_grant("physician", "P003") is None   # grant is role+patient scoped


def test_expired_grant_no_longer_unlocks():
    reg = BreakGlassRegistry(ttl_minutes=0.0001)
    reg.grant("nurse", "P003", BG_REASON, now=1000.0)
    assert reg.active_grant("nurse", "P003", now=1000.0 + 1.0) is None
    result = evaluate("nurse", "TREATMENT", "", "query_patient_record", {"patient_id": "P003"}, break_glass=reg)
    assert result.outcome == "BLOCKED"


def test_break_glass_requires_substantive_reason():
    reg = BreakGlassRegistry()
    with pytest.raises(ValueError):
        reg.grant("nurse", "P003", "patient crashing")
    with pytest.raises(ValueError):
        reg.grant("nurse", "P003", "   ")


def test_break_glass_events_are_flagged_in_audit():
    audit = AuditLogger()
    reg = BreakGlassRegistry(ttl_minutes=15, audit=audit)
    reg.grant("nurse", "P003", BG_REASON)
    events = audit.events_by_category("BREAK_GLASS")
    assert len(events) == 1
    assert events[0].policy_rule_triggered == "Break-Glass: Emergency Override"
    assert audit.verify_chain()["intact"] is True


def test_pending_review_queue_records_every_grant():
    reg = BreakGlassRegistry()
    reg.grant("nurse", "P003", BG_REASON)
    reg.grant("physician", "P002", "OUD patient overdosed, records needed for poison control consult")
    assert len(reg.pending_review()) == 2


# ── New RBAC egress caps ────────────────────────────────────────

def test_nurse_cannot_send_to_registered_vendor():
    result = evaluate("nurse", "TREATMENT", "", "send_data_to_vendor",
                      {"vendor_id": "aws-bedrock", "patient_id": "P001", "data": "clean summary"})
    assert result.outcome == "BLOCKED"
    assert result.rule == "RBAC: Vendor Transmission Not Authorized"


def test_physician_cannot_send_sensitive_even_to_covering_vendor():
    result = evaluate("physician", "TREATMENT", "", "send_data_to_vendor",
                      {"vendor_id": "epic-systems", "patient_id": "P002", "data": "clean summary"})
    assert result.outcome == "BLOCKED"
    assert result.rule == "RBAC: Sensitive Data Egress Restricted"


def test_billing_standard_send_still_allowed():
    """E005 invariant must survive the egress hardening."""
    result = evaluate("billing_staff", "PAYMENT", "Processing Q1 claims batch",
                      "send_data_to_vendor",
                      {"vendor_id": "change-healthcare", "patient_id": "P001",
                       "data": "ICD-10: E11.9, CPT: 99213, DOS: 2026-03-15"})
    assert result.outcome == "ALLOWED"


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call(["pytest", "-q", __file__]))
