"""
tests/test_jev_preflight.py
───────────────────────────
Offline tests for the Jev preflight layer (app/jev/guardrails.py).

Three guarantees are under test:

  1. CI stays offline. With no key and no network every path resolves to
     the deterministic stand-ins, and the model is never called.
  2. The engine stays authoritative. An advisory never changes outcome,
     rule, or reason, and a BLOCK always triages to escalate.
  3. The model annotates, code branches. A model answer can enrich the
     reason for a human reviewer; it cannot move the lane.

No network, no API key, no patient text: every payload here is synthetic.
"""

from __future__ import annotations

import pytest

from app.guardrails.policy_engine import evaluate
from app.jev.checks import NETWORK_ENV_VAR, network_enabled
from app.jev.decisions import JevAnswer, JevConfigError, JevResponse
from app.jev.guardrails import (
    DEIDENTIFY,
    ESCALATE,
    LIVE_SOURCE,
    OFFLINE_SOURCE,
    PreflightAdvisory,
    ambiguity_flags,
    make_adviser,
    preflight,
)

# A payload with narrative birth/address cues and no high-confidence regex
# match — the regex blind spot the engine warns about but cannot block.
_NARRATIVE_PAYLOAD = "the patient born in March of eighty-five lives on Maple Street"


def _evaluate(
    *,
    role: str = "physician",
    purpose: str = "TREATMENT",
    justification: str = "",
    tool_name: str = "query_patient_record",
    tool_inputs: dict | None = None,
    adviser=None,
):
    return evaluate(
        role=role,
        purpose=purpose,
        justification=justification,
        tool_name=tool_name,
        tool_inputs=tool_inputs if tool_inputs is not None else {"patient_id": "P001"},
        adviser=adviser,
    )


def _response(**answers) -> JevResponse:
    parsed = {
        qid: JevAnswer(qid, kind, value, confidence=0.9)
        for qid, (kind, value) in answers.items()
    }
    return JevResponse(
        answers=parsed, latency_ms=204.0, provider="TypeSafe", model_resolved="jev-1.13"
    )


class FakeAsk:
    """Stand-in for ask_jev: records what it was asked, returns a canned response."""

    def __init__(self, response: JevResponse | None = None, exc: Exception | None = None):
        self.response = response
        self.exc = exc
        self.calls: list[dict] = []

    def __call__(self, state, questions, *, key_path=None):
        self.calls.append({"state": state, "questions": questions, "key_path": key_path})
        if self.exc is not None:
            raise self.exc
        return self.response


def _explode(*args, **kwargs):
    raise AssertionError("the model must not be called offline")


# ─────────────────────────────────────────────────────────────────────────────
# Ambiguity gating
# ─────────────────────────────────────────────────────────────────────────────

def test_unambiguous_result_gets_no_preflight():
    """Physician + TREATMENT + STANDARD record owes no reason and is unambiguous."""
    result = _evaluate()

    assert result.outcome == "ALLOWED"
    assert ambiguity_flags(result) == ()
    assert preflight(result, allow_network=False) is None


def test_novel_tool_is_ambiguous_but_engine_still_allows():
    result = _evaluate(tool_name="export_patient_csv", tool_inputs={})

    assert result.outcome == "ALLOWED"
    assert "novel_tool" in ambiguity_flags(result)


def test_unknown_vendor_is_ambiguous_and_engine_blocks():
    result = _evaluate(
        tool_name="send_data_to_vendor",
        tool_inputs={"vendor_id": "shadow-llm", "patient_id": "P001"},
    )

    assert result.outcome == "BLOCKED"
    assert result.rule == "BAA: Unregistered Vendor"
    assert "unknown_vendor" in ambiguity_flags(result)


def test_justification_owed_is_false_when_a_reason_is_on_file():
    silent = _evaluate(tool_name="log_clinical_note", tool_inputs={"note": "x", "patient_id": "P001"})
    explicit = _evaluate(
        justification="documenting the visit",
        tool_name="log_clinical_note",
        tool_inputs={"note": "x", "patient_id": "P001"},
    )

    assert "justification_owed" in ambiguity_flags(silent)
    assert "justification_owed" not in ambiguity_flags(explicit)


# ─────────────────────────────────────────────────────────────────────────────
# The lane is decided in code, offline
# ─────────────────────────────────────────────────────────────────────────────

def test_offline_fallback_escalates_on_unresolved_ambiguity():
    result = _evaluate(tool_name="export_patient_csv", tool_inputs={})

    advisory = preflight(result, allow_network=False)

    assert isinstance(advisory, PreflightAdvisory)
    assert advisory.triage == ESCALATE
    assert advisory.source == OFFLINE_SOURCE
    assert advisory.model == OFFLINE_SOURCE
    assert advisory.confidence is None and advisory.latency_ms == 0.0
    assert "human review" in advisory.rationale


def test_offline_fallback_deidentifies_on_phi_pattern_gap():
    result = _evaluate(
        tool_name="send_data_to_vendor",
        tool_inputs={"vendor_id": "azure-openai", "data": _NARRATIVE_PAYLOAD},
    )

    assert result.outcome == "ALLOWED", "narrative cues must stay below the block threshold"
    assert result.phi_narrative_cues is True
    assert "phi_pattern_gap" in ambiguity_flags(result)
    assert preflight(result, allow_network=False).triage == DEIDENTIFY


def test_offline_fallback_confirms_escalation_on_engine_block():
    """Nurse reading a RESTRICTED record is blocked; the advisory agrees, never overturns."""
    result = _evaluate(
        role="nurse",
        tool_name="query_patient_record",
        tool_inputs={"patient_id": "P003"},
    )

    assert result.outcome == "BLOCKED"
    advisory = preflight(result, allow_network=False)
    assert advisory.triage == ESCALATE
    assert advisory.engine_outcome == "BLOCKED"
    assert "overturn" in advisory.rationale


def test_offline_path_never_calls_the_model():
    result = _evaluate(tool_name="export_patient_csv", tool_inputs={})

    advisory = preflight(result, allow_network=False, ask=_explode)

    assert advisory.source == OFFLINE_SOURCE


# ─────────────────────────────────────────────────────────────────────────────
# Offline annotations — the same composition, no network
# ─────────────────────────────────────────────────────────────────────────────

def test_novel_tool_annotation_classifies_by_verb_offline():
    result = _evaluate(tool_name="export_patient_csv", tool_inputs={})

    advisory = preflight(result, allow_network=False)

    assert advisory.triage == ESCALATE                      # annotation never lowers it
    assert advisory.annotations and "transmits_external" in advisory.annotations[0]
    assert "transmits_external" in advisory.summary()


def test_unknown_vendor_annotation_flags_shadow_ai_offline():
    result = _evaluate(
        tool_name="send_data_to_vendor",
        tool_inputs={"vendor_id": "claude-desktop", "patient_id": "P001"},
    )

    advisory = preflight(result, allow_network=False)

    assert advisory.triage == ESCALATE
    assert "shadow-AI" in advisory.annotations[0]


def test_unknown_vendor_annotation_distinguishes_unregistered_system():
    result = _evaluate(
        tool_name="send_data_to_vendor",
        tool_inputs={"vendor_id": "some-clinic-portal", "patient_id": "P001"},
    )

    advisory = preflight(result, allow_network=False)

    assert "unregistered system" in advisory.annotations[0]


def test_justification_owed_gets_no_model_annotation():
    result = _evaluate(tool_name="log_clinical_note", tool_inputs={"note": "x", "patient_id": "P001"})

    advisory = preflight(result, allow_network=False)

    assert advisory.triage == ESCALATE
    assert advisory.annotations == ()


# ─────────────────────────────────────────────────────────────────────────────
# Live path — the model annotates, code still branches
# ─────────────────────────────────────────────────────────────────────────────

def test_live_annotation_comes_from_the_model():
    result = _evaluate(tool_name="export_patient_csv", tool_inputs={})
    ask = FakeAsk(_response(tool_intent=("choice", "writes_clinical_documentation")))

    advisory = preflight(result, allow_network=True, ask=ask)

    assert advisory.source == LIVE_SOURCE
    assert advisory.triage == ESCALATE                      # lane unchanged by the model
    assert "writes_clinical_documentation" in advisory.annotations[0]
    assert advisory.confidence == pytest.approx(0.9)
    assert advisory.latency_ms == pytest.approx(204.0)
    assert ask.calls[0]["state"] == {"tool": "export_patient_csv"}


def test_live_path_sends_only_the_identifier_not_the_result():
    result = _evaluate(
        tool_name="send_data_to_vendor",
        tool_inputs={"vendor_id": "claude-desktop", "patient_id": "P001", "data": _NARRATIVE_PAYLOAD},
    )
    ask = FakeAsk(_response(is_consumer_platform=("noul", 0.95)))

    preflight(result, allow_network=True, ask=ask)

    state = ask.calls[0]["state"]
    assert state == {"vendor_id": "claude-desktop"}
    assert _NARRATIVE_PAYLOAD not in str(state)
    assert "patient_id" not in state


def test_live_failure_degrades_to_the_deterministic_fallback():
    """A missing key or a dead endpoint must not raise out of the caller."""
    result = _evaluate(tool_name="export_patient_csv", tool_inputs={})
    ask = FakeAsk(exc=JevConfigError("Jev API key file not readable: /nope"))

    advisory = preflight(result, allow_network=True, ask=ask)

    assert advisory.source == OFFLINE_SOURCE
    assert advisory.triage == ESCALATE
    assert "JevConfigError" in advisory.error
    assert "fallback" in advisory.summary()


# ─────────────────────────────────────────────────────────────────────────────
# policy_engine adviser hook
# ─────────────────────────────────────────────────────────────────────────────

def test_adviser_hook_attaches_preflight_without_changing_the_verdict():
    def _run(adviser):
        return _evaluate(
            role="nurse",
            tool_name="query_patient_record",
            tool_inputs={"patient_id": "P003"},
            adviser=adviser,
        )

    plain = _run(None)
    advised = _run(make_adviser(allow_network=False))

    assert (plain.outcome, plain.rule, plain.reason) == (
        advised.outcome, advised.rule, advised.reason
    )
    assert plain.preflight is None
    assert advised.preflight is not None
    assert advised.preflight.triage == ESCALATE
    assert advised.preflight.engine_outcome == "BLOCKED"


def test_adviser_leaves_an_existing_advisory_untouched():
    """The engine's own NLP-gap note wins; the preflight note only fills a hole."""
    def _run(adviser):
        return _evaluate(
            tool_name="send_data_to_vendor",
            tool_inputs={"vendor_id": "azure-openai", "data": _NARRATIVE_PAYLOAD},
            adviser=adviser,
        )

    plain = _run(None)
    advised = _run(make_adviser(allow_network=False))

    assert plain.advisory and "narrative PHI cues" in plain.advisory
    assert advised.advisory == plain.advisory
    assert advised.preflight is not None


def test_adviser_note_fills_an_empty_advisory_slot():
    result = _evaluate(
        tool_name="export_patient_csv",
        tool_inputs={},
        adviser=make_adviser(allow_network=False),
    )

    assert result.advisory is not None
    assert "Jev preflight" in result.advisory
    assert result.preflight.triage == ESCALATE


def test_no_adviser_means_zero_behavior_change():
    result = _evaluate(tool_name="export_patient_csv", tool_inputs={})

    assert result.preflight is None
    assert result.advisory is None


def test_adviser_hook_is_silent_on_unambiguous_requests():
    result = _evaluate(adviser=make_adviser(allow_network=False))

    assert result.outcome == "ALLOWED"
    assert result.preflight is None
    assert result.advisory is None


# ─────────────────────────────────────────────────────────────────────────────
# Network opt-in default
# ─────────────────────────────────────────────────────────────────────────────

def test_network_is_off_by_default_and_env_gated(monkeypatch):
    monkeypatch.delenv(NETWORK_ENV_VAR, raising=False)
    assert network_enabled() is False

    monkeypatch.setenv(NETWORK_ENV_VAR, "1")
    assert network_enabled() is True
    monkeypatch.setenv(NETWORK_ENV_VAR, "off")
    assert network_enabled() is False
