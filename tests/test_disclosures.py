"""
tests/test_disclosures.py
────────────────────────
Accounting of disclosures (45 CFR §164.528) rendered from the audit chain.

Invariants:
  - Only DISCLOSURE and BREAK_GLASS events are reportable; everything else
    is reviewed and counted as excluded
  - Rows carry the evidence fields a privacy office needs
  - The report states whether the underlying audit chain is intact
"""

from app.compliance.disclosures import disclosure_report
from app.guardrails.audit_logger import AuditLogger


def _seed(logger: AuditLogger):
    logger.log(category="DISCLOSURE", outcome="SUCCESS", actor_role="billing_staff", actor_id="rc-2",
               tool_name="send_data_to_vendor", action_description="Claims batch to processor",
               patient_id="P001", vendor_id="change-healthcare", purpose_of_use="PAYMENT")
    logger.log(category="POLICY_EVAL", outcome="BLOCKED", actor_role="nurse", actor_id="rn-7",
               tool_name="query_patient_record", action_description="Blocked restricted access",
               policy_rule_triggered="Sensitivity Tier: Access Denied")
    logger.log(category="ACCESS", outcome="SUCCESS", actor_role="physician", actor_id="dr-k",
               tool_name="query_patient_record", action_description="Record accessed", patient_id="P001")
    logger.log(category="BREAK_GLASS", outcome="WARNING", actor_role="nurse", actor_id="rn-7",
               tool_name="break_glass_grant", action_description="EMERGENCY OVERRIDE granted for P003",
               patient_id="P003", policy_rule_triggered="Break-Glass: Emergency Override")


def test_only_disclosure_and_break_glass_are_reportable():
    logger = AuditLogger()
    _seed(logger)
    report = disclosure_report(logger)
    assert len(report.rows) == 2
    assert {r.category for r in report.rows} == {"DISCLOSURE", "BREAK_GLASS"}
    assert report.excluded_events == 2


def test_break_glass_rows_name_the_emergency_recipient():
    logger = AuditLogger()
    _seed(logger)
    report = disclosure_report(logger)
    bg = next(r for r in report.rows if r.category == "BREAK_GLASS")
    assert bg.recipient == "emergency access (break-glass)"
    assert bg.patient_id == "P003"


def test_vendor_disclosure_rows_carry_evidence_fields():
    logger = AuditLogger()
    _seed(logger)
    report = disclosure_report(logger)
    row = next(r for r in report.rows if r.category == "DISCLOSURE")
    assert row.recipient == "change-healthcare"
    assert row.purpose == "PAYMENT"
    assert row.actor_role == "billing_staff"
    assert row.event_id and row.timestamp


def test_report_states_chain_integrity():
    logger = AuditLogger()
    _seed(logger)
    report = disclosure_report(logger)
    assert report.chain_intact is True
    logger.events[0].action_description = "tampered"
    assert disclosure_report(logger).chain_intact is False


def test_text_and_csv_renderings():
    logger = AuditLogger()
    _seed(logger)
    report = disclosure_report(logger)
    text = report.to_text()
    assert "ACCOUNTING OF DISCLOSURES" in text and "INTACT" in text
    header = report.to_csv().decode().splitlines()[0]
    assert "recipient" in header and "patient_id" in header


def test_summary_aggregates_by_recipient_and_patient():
    logger = AuditLogger()
    _seed(logger)
    s = disclosure_report(logger).summary()
    assert s["reportable_disclosures"] == 2
    assert s["by_recipient"]["change-healthcare"] == 1
    assert s["by_recipient"]["emergency access (break-glass)"] == 1
    assert s["by_patient"] == {"P001": 1, "P003": 1}


def test_empty_log_renders_clean_report():
    report = disclosure_report(AuditLogger())
    assert report.rows == [] and report.excluded_events == 0 and report.chain_intact is True
    assert "No reportable disclosures" in report.to_text()


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call(["pytest", "-q", __file__]))
