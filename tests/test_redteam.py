"""
tests/test_redteam.py
──────────────────────
Pytest runner for the prompt-injection red-team eval suite.

No LLM and no strands imports — every case runs directly against the
deterministic policy engine (app/guardrails/policy_engine.py), so the
suite runs in CI with no API credentials.

Headline invariants verified here:
  1. Every POLICY_BYPASS case is BLOCKED with a specific rule
     → attack success rate = 0.
  2. Hostile prompt rhetoric alone never changes an outcome — only the
     structured session context + tool call does.
  3. Every DETECTION_GAP case is ALLOWED and documents its production
     mitigation (NER layer).

Run with: pytest tests/test_redteam.py -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from app.evals.redteam_cases import REDTEAM_CASES, RedTeamCase
from app.guardrails.policy_engine import evaluate


def run_case(case: RedTeamCase):
    """
    Run the engine exactly as the enforcement point would: authenticated
    session context + the structured tool call. attack_prompt is never
    passed to evaluate() — that's the design being tested.
    """
    return evaluate(case.role, case.purpose, case.justification, case.tool_name, case.tool_inputs)


# ── Parametrized red-team cases ─────────────────────────────────

@pytest.mark.parametrize("case", REDTEAM_CASES, ids=[c.case_id for c in REDTEAM_CASES])
def test_redteam_case(case: RedTeamCase):
    """Each red-team case must produce exactly its documented outcome and rule."""
    result = run_case(case)

    assert result.outcome == case.expected_outcome, (
        f"\n[{case.case_id}] {case.description}\n"
        f"Category: {case.category} | Attack class: {case.attack_class}\n"
        f"Expected: {case.expected_outcome} | Got: {result.outcome}\n"
        f"Expected rule: {case.expected_rule} | Got rule: {result.rule}\n"
        f"Rationale: {case.rationale}"
    )

    if case.expected_outcome == "BLOCKED":
        assert result.rule == case.expected_rule, (
            f"\n[{case.case_id}] Wrong rule triggered.\n"
            f"Expected: {case.expected_rule}\n"
            f"Got: {result.rule}\n"
            f"Rationale: {case.rationale}"
        )
    else:
        assert result.rule is None, (
            f"\n[{case.case_id}] ALLOWED case unexpectedly carries a rule: {result.rule}"
        )


# ── Headline: zero attack success rate on policy bypass ─────────

def test_policy_bypass_attack_success_rate_is_zero():
    """
    Every POLICY_BYPASS case must be BLOCKED. Any survivor means an
    attacker found a path through the policy engine — the headline
    metric for this suite must stay at exactly 0.
    """
    bypass_cases = [c for c in REDTEAM_CASES if c.attack_class == "POLICY_BYPASS"]
    breached = [
        c for c in bypass_cases
        if run_case(c).outcome != "BLOCKED"
    ]
    assert breached == [], (
        "\nPOLICY BYPASS DETECTED — attack success rate is nonzero:\n"
        + "\n".join(
            f"  {c.case_id}: {c.description} (expected rule: {c.expected_rule})"
            for c in breached
        )
    )


# ── Detection gaps must stay documented ─────────────────────────

def test_detection_gaps_are_documented():
    """
    DETECTION_GAP cases are expected ALLOWED — they document where regex
    legitimately fails. Each must carry a rationale that names the
    production mitigation so the gap is acknowledged, not silent.
    """
    gap_cases = [c for c in REDTEAM_CASES if c.attack_class == "DETECTION_GAP"]
    assert gap_cases, "Red-team suite must contain DETECTION_GAP cases"

    for case in gap_cases:
        result = run_case(case)
        assert result.outcome == "ALLOWED", (
            f"\n[{case.case_id}] Detection-gap case now blocks — the engine changed. "
            f"Re-verify the payload and update the documented gap.\n"
            f"Got rule: {result.rule}"
        )
        assert case.rationale.strip(), f"[{case.case_id}] Detection gap has no rationale"
        assert any(k in case.rationale for k in ("NER", "Comprehend", "Presidio")), (
            f"[{case.case_id}] Detection-gap rationale must name the production "
            f"mitigation (NER layer: AWS Comprehend Medical / Microsoft Presidio)"
        )


# ── Closed gaps must stay closed ────────────────────────────────

def test_closed_gaps_stay_closed():
    """
    CLOSED_GAP cases are former detection gaps that a hardening fix now
    catches. They are kept as regression tests: if one ever evaluates
    ALLOWED again, the fix regressed.
    """
    closed = [c for c in REDTEAM_CASES if c.attack_class == "CLOSED_GAP"]
    assert closed, "Suite should retain closed-gap regressions"
    for case in closed:
        result = run_case(case)
        assert result.outcome == "BLOCKED", (
            f"\n[{case.case_id}] CLOSED GAP REGRESSED — a fixed detection gap "
            f"passes again (got {result.outcome} / {result.rule})."
        )
        assert case.rationale.strip(), f"[{case.case_id}] Closed gap has no rationale"
        assert "originally" in case.rationale.lower(), (
            f"[{case.case_id}] Closed-gap rationale must record what the original gap was"
        )


# ── Injection invariants ────────────────────────────────────────

def test_injection_flavors_present():
    """Both documented injection flavors must exist in the suite."""
    injections = [c for c in REDTEAM_CASES if c.attack_class == "PROMPT_INJECTION"]
    clean_flavor = [c for c in injections if c.expected_outcome == "ALLOWED"]
    violating_flavor = [c for c in injections if c.expected_outcome == "BLOCKED"]
    assert injections, "Red-team suite must contain PROMPT_INJECTION cases"
    assert clean_flavor and violating_flavor, (
        "Injection suite needs both flavors: hostile prompt + clean call (ALLOWED) "
        "and hostile prompt + violating call (BLOCKED)"
    )
    for case in injections:
        assert case.attack_prompt.strip(), (
            f"[{case.case_id}] Injection case must carry its hostile prompt text"
        )


if __name__ == "__main__":
    print("Running prompt-injection red-team suite...\n")
    passed = 0
    failed = 0
    stats: dict[str, dict[str, int]] = {}

    for case in REDTEAM_CASES:
        result = run_case(case)
        ok = result.outcome == case.expected_outcome and (
            case.expected_outcome != "BLOCKED" or result.rule == case.expected_rule
        )
        tag = "✅ PASS" if ok else "❌ FAIL"
        print(f"{tag} {case.case_id} [{case.attack_class}] {case.description}")
        if not ok:
            print(f"       Expected: {case.expected_outcome} / {case.expected_rule} | "
                  f"Got: {result.outcome} / {result.rule}")
            failed += 1
        else:
            passed += 1

        s = stats.setdefault(case.attack_class, {"total": 0, "blocked": 0, "breached": 0})
        s["total"] += 1
        if result.outcome == "BLOCKED":
            s["blocked"] += 1
        if case.attack_class == "POLICY_BYPASS" and result.outcome != "BLOCKED":
            s["breached"] += 1

    print("\n── Red-team summary by attack class ─────────────────")
    print(f"{'ATTACK_CLASS':<18}{'cases':>7}{'blocked':>9}{'breached':>10}")
    bypass_total = bypass_breached = 0
    for cls in ("POLICY_BYPASS", "PROMPT_INJECTION", "DETECTION_GAP", "CLOSED_GAP"):
        s = stats.get(cls, {"total": 0, "blocked": 0, "breached": 0})
        print(f"{cls:<18}{s['total']:>7}{s['blocked']:>9}{s['breached']:>10}")
        if cls == "POLICY_BYPASS":
            bypass_total, bypass_breached = s["total"], s["breached"]

    pct = (bypass_breached / bypass_total * 100) if bypass_total else 0.0
    print(f"\nATTACK SUCCESS RATE (policy bypass): {bypass_breached}/{bypass_total} ({pct:.1f}%)")
    print(f"\n{passed}/{passed+failed} cases passed.")
