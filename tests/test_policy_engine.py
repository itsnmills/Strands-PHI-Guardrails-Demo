"""
tests/test_policy_engine.py
───────────────────────────
Parity tests for the shared deterministic policy engine
(app/guardrails/policy_engine.py) against the eval-case suite.

No LLM and no Streamlit — pure stdlib policy evaluation.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from app.evals.eval_cases import EVAL_CASES, EvalCase
from app.guardrails.policy_engine import evaluate, CONTROL_ORDER


@pytest.mark.parametrize("case", EVAL_CASES, ids=[c.case_id for c in EVAL_CASES])
def test_engine_matches_expected(case: EvalCase):
    result = evaluate(
        role=case.role,
        purpose=case.purpose,
        justification=case.justification,
        tool_name=case.tool_name,
        tool_inputs=case.tool_inputs,
    )

    assert result.outcome == case.expected_outcome, (
        f"[{case.case_id}] {case.description}\n"
        f"expected={case.expected_outcome} got={result.outcome} rule={result.rule}\n"
        f"rationale: {case.rationale}"
    )
    if case.expected_outcome == "BLOCKED" and case.expected_rule:
        assert result.rule == case.expected_rule, (
            f"[{case.case_id}] expected rule '{case.expected_rule}', got '{result.rule}'"
        )


@pytest.mark.parametrize("case", EVAL_CASES, ids=[c.case_id for c in EVAL_CASES])
def test_engine_trace_invariants(case: EvalCase):
    result = evaluate(
        role=case.role,
        purpose=case.purpose,
        justification=case.justification,
        tool_name=case.tool_name,
        tool_inputs=case.tool_inputs,
    )

    assert set(result.trace.keys()) == {cid for cid, _ in CONTROL_ORDER}
    statuses = [step.status for step in result.steps]

    assert statuses.count("block") <= 1, "at most one control may block"

    if result.outcome == "BLOCKED":
        assert "block" in statuses, "a blocked result must have a blocking control"
        first_block = statuses.index("block")
        assert all(s == "skip" for s in statuses[first_block + 1:]), (
            "controls after the blocking control must be skipped"
        )
        assert all(s in ("pass", "skip", "warn") for s in statuses[:first_block])
    else:
        assert "block" not in statuses
        assert statuses[statuses.index("minnec") if "minnec" in statuses else -1] != "block"
