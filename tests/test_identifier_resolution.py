"""
tests/test_identifier_resolution.py
───────────────────────────────────
Patient identifiers must resolve the same way in the policy layer and the
tool layer — models/humans type names ("Sarah Connor") as often as IDs.

Invariants:
  - IDs resolve case-insensitively ('p003' → 'P003')
  - Full names resolve to exactly one patient
  - Unresolvable references return None (no guessing)
  - The policy engine applies sensitivity/RBAC checks to RESOLVED identifiers,
    so a name-based call cannot dodge a tier block
"""

from app.data.patients import resolve_patient_id
from app.guardrails.policy_engine import evaluate


# ── Resolver ────────────────────────────────────────────────────

def test_ids_resolve_case_insensitively():
    assert resolve_patient_id("P003") == "P003"
    assert resolve_patient_id("p003") == "P003"
    assert resolve_patient_id("  P001  ") == "P001"


def test_names_resolve_uniquely():
    assert resolve_patient_id("Sarah Connor") == "P003"
    assert resolve_patient_id("sarah connor") == "P003"
    assert resolve_patient_id("Jane Doe") == "P001"
    assert resolve_patient_id("Robert Chen") == "P004"


def test_unresolvable_references_return_none():
    assert resolve_patient_id("Dr. Patel") is None
    assert resolve_patient_id("P999") is None
    assert resolve_patient_id("") is None
    assert resolve_patient_id(None) is None


# ── Engine applies policy to resolved identifiers ───────────────

def test_name_based_restricted_query_is_blocked():
    """Nurse asks for 'Sarah Connor' by name — must resolve to P003 and block."""
    result = evaluate("nurse", "TREATMENT", "", "query_patient_record", {"patient_id": "Sarah Connor"})
    assert result.patient_id == "P003"
    assert result.outcome == "BLOCKED"
    assert result.rule == "Sensitivity Tier: Access Denied"


def test_name_based_standard_query_allowed_and_resolved():
    result = evaluate("physician", "TREATMENT", "", "query_patient_record", {"patient_id": "jane doe"})
    assert result.patient_id == "P001"
    assert result.outcome == "ALLOWED"


def test_name_resolution_applies_to_vendor_sends():
    """Sensitive-tier egress check must see the resolved patient for name refs."""
    result = evaluate("physician", "TREATMENT", "", "send_data_to_vendor",
                      {"vendor_id": "epic-systems", "patient_id": "John Smith", "data": "clean summary"})
    assert result.patient_id == "P002"
    assert result.outcome == "BLOCKED"
    assert result.rule == "RBAC: Sensitive Data Egress Restricted"


def test_unknown_patient_cannot_dodge_tier_checks():
    """An unresolvable name is not a bypass: it's simply an unknown patient —
    recognizable IDs still block, and unknown ones never grant elevated access."""
    result = evaluate("nurse", "TREATMENT", "", "query_patient_record", {"patient_id": "Nobody McNobody"})
    assert result.patient_id == "Nobody McNobody"
    assert result.outcome == "ALLOWED"  # no patient record exists to protect; tool will 404
    assert result.trace["sens"].status == "skip"


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call(["pytest", "-q", __file__]))
