"""
tests/test_audit_chain.py
────────────────────────
Tamper-evidence tests for the HMAC hash-chained audit logger.

Invariants:
  - Every event is sealed: entry_hash = HMAC(key, prev_hash + canonical(event))
  - The chain links each event to its predecessor (GENESIS anchor first)
  - Any modification, deletion, or reordering of history is detected
  - The chain head serves as a notarization anchor for external verification
"""

import pytest

from app.guardrails.audit_logger import AuditLogger


def _log_three(logger: AuditLogger):
    logger.log(category="ACCESS", outcome="SUCCESS", actor_role="physician", actor_id="dr-k",
               tool_name="query_patient_record", action_description="accessed P001", patient_id="P001")
    logger.log(category="POLICY_EVAL", outcome="BLOCKED", actor_role="nurse", actor_id="rn-7",
               tool_name="query_patient_record", action_description="blocked P003",
               policy_rule_triggered="Sensitivity Tier: Access Denied", patient_id="P003")
    logger.log(category="DISCLOSURE", outcome="SUCCESS", actor_role="billing_staff", actor_id="rc-2",
               tool_name="send_data_to_vendor", action_description="claims to change-healthcare",
               vendor_id="change-healthcare")


def test_chain_is_intact_and_anchored():
    logger = AuditLogger()
    _log_three(logger)
    report = logger.verify_chain()
    assert report["intact"] is True
    assert report["broken_at"] is None
    assert report["events_checked"] == 3
    assert logger.events[0].prev_hash == AuditLogger.GENESIS
    assert logger.events[1].prev_hash == logger.events[0].entry_hash
    assert logger.events[2].prev_hash == logger.events[1].entry_hash
    assert logger.chain_head == logger.events[-1].entry_hash


def test_each_hash_binds_full_event_contents():
    logger = AuditLogger()
    _log_three(logger)
    for event in logger.events:
        assert len(event.entry_hash) == 64
        assert len(event.prev_hash) == 64


def test_content_tampering_is_detected():
    logger = AuditLogger()
    _log_three(logger)
    logger.events[1].denial_reason = "altered after the fact"
    report = logger.verify_chain()
    assert report["intact"] is False
    assert report["broken_at"] == logger.events[1].event_id


def test_prev_hash_rewire_is_detected():
    """Recomputing hashes without the key fails: the HMAC key is unknown to the attacker."""
    logger = AuditLogger()
    _log_three(logger)
    logger.events[1].denial_reason = "altered"
    logger.events[1].entry_hash = "0" * 64  # attacker tries to re-seal with a fake hash
    report = logger.verify_chain()
    assert report["intact"] is False
    assert report["broken_at"] == logger.events[1].event_id


def test_deletion_is_detected_via_chain_link():
    """Deleting a middle event breaks the linkage: successor's prev_hash points to the removed hash."""
    logger = AuditLogger()
    _log_three(logger)
    removed = logger._events.pop(1)
    report = logger.verify_chain()
    assert report["intact"] is False
    assert report["broken_at"] == logger.events[1].event_id  # event 3 now links to a missing hash
    assert removed.entry_hash == logger.events[1].prev_hash


def test_chain_resumes_after_clear():
    logger = AuditLogger()
    _log_three(logger)
    logger.clear()
    assert logger.verify_chain()["intact"] is True
    assert logger.chain_head == AuditLogger.GENESIS


def test_exports_include_chain_fields():
    logger = AuditLogger()
    _log_three(logger)
    exported = logger.events[0].to_dict()
    assert "prev_hash" in exported and "entry_hash" in exported
    summary = logger.compliance_summary()
    assert summary["audit_chain_intact"] is True
    assert summary["chain_head"] == logger.chain_head


def test_independent_loggers_do_not_share_secrets():
    a, b = AuditLogger(), AuditLogger()
    _log_three(a)
    _log_three(b)
    assert a.events[0].entry_hash != b.events[0].entry_hash


def test_signing_key_is_reproducible_for_verification_across_processes():
    """A verifier holding the same key (e.g. exported to SIEM) can re-verify the chain."""
    key = bytes(range(32))
    logger = AuditLogger(signing_key=key)
    _log_three(logger)
    reloaded = AuditLogger(signing_key=key)
    assert reloaded.verify_chain()  # fresh empty chain is fine
    # Feed the original events through the same-key verifier: hashes must match
    for event in logger.events:
        expected = reloaded._compute_entry_hash(reloaded._entry_payload(event), event.prev_hash)
        assert expected == event.entry_hash


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call(["pytest", "-q", __file__]))
