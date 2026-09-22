"""
app/jev/guardrails.py
─────────────────────
Offline-safe Jev preflight layer for the deterministic HIPAA engine.

Deployment shape (measured, not assumed)
----------------------------------------
The trials in `trial/` put Jev in front of the full 58-case suite and the
45-case ambiguity subset. What they showed:

  - Asked to judge legitimacy, Jev re-litigated concrete policy blocks and
    recommended "allow" on them. It is not a policy reasoner and must not
    be asked to be one. That question is gone.
  - On the cases the engine cannot resolve from policy alone it never
    recommended "allow" over a block. That is the slice worth consulting.

So the lane is never decided by a model here. It is decided by `if`
statements in `app/jev/checks.py` from deterministic ambiguity flags:

    novel_tool             tool outside the known surface
    unknown_vendor         vendor in neither the BAA registry nor the blocklist
    justification_owed     a reason is semantically owed but absent
    phi_pattern_gap        PHI cues a regex cannot confirm (or sees below
                           the block threshold)

What the model contributes is an *annotation*, never a branch: for a novel
tool or an unknown vendor it says what the thing looks like ("classified as
'transmits_external'", "looks like a consumer AI platform"), which is what a
human reviewer needs and what a regex cannot say. Jev is the input to an if
statement, not the if statement.

    engine BLOCKED                     -> escalate (never contradict)
    allowed, unconfirmed PHI pattern   -> deidentify
    allowed, anything else ambiguous   -> escalate

Two transports, one control flow
--------------------------------
Each check runs live (Jev) or offline (a regex stand-in) through the same
composition, so thresholds behave identically in CI and production, and CI
needs no key and no network. `phi_pattern_gap` is deliberately resolved
without a model call — judging it would mean shipping payload text out, and
the offline floor (redact before egress) is already the safe answer.

Authority boundary
------------------
Nothing here changes the engine's verdict, outcome, rule, or reason. On an
engine BLOCK the triage is escalate; a model can only add caution. If a
model is unreachable, the offline stand-in answers and the error is recorded
rather than raised.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from app.guardrails.phi_detector import should_block
from app.guardrails.policy_engine import CLINICAL_TOOLS
from app.data.vendors import VENDOR_REGISTRY, BLOCKED_PLATFORMS
from app.data.patients import PATIENT_DB
from app.jev.checks import (
    TOOL_CHECK,
    VENDOR_CHECK,
    Check,
    Verdict,
    network_enabled,
    run as run_check,
)
from app.jev.decisions import ask_jev

ALLOW = "allow"
DEIDENTIFY = "deidentify"
ESCALATE = "escalate"
VALID_TRIAGE = frozenset({ALLOW, DEIDENTIFY, ESCALATE})

LIVE_SOURCE = "jev"
OFFLINE_SOURCE = "deterministic_fallback"

# The known tool surface. Anything outside it is a novel_tool ambiguity, not
# an automatic allow or block — the engine still owns the verdict.
KNOWN_TOOLS: frozenset[str] = frozenset(CLINICAL_TOOLS) | {
    "check_vendor_baa_status",
    "call_llm",
}

# Tools where an unwritten reason is semantically owed even when the
# purpose-of-use policy does not demand one: an external send or a write.
_EGRESS_OR_WRITE_TOOLS: frozenset[str] = frozenset(
    {"send_data_to_vendor", "log_clinical_note", "call_llm"}
)

_SENSITIVE_TIERS: frozenset[str] = frozenset({"SENSITIVE", "RESTRICTED"})

# Which atomic check annotates which structural flag. Neither can move a lane.
_CHECK_FOR_FLAG: dict[str, Check] = {
    "unknown_vendor": VENDOR_CHECK,
    "novel_tool": TOOL_CHECK,
}


@dataclass(frozen=True)
class PreflightAdvisory:
    """A second opinion on an ambiguous request. Never authoritative.

    `triage` is computed in code from the ambiguity flags and the engine
    outcome. `annotations` are the model's (or the offline stand-in's) labels
    for the structural signals — context for the human, not a branch.
    """

    triage: str                       # allow | deidentify | escalate
    source: str                       # "jev" | "deterministic_fallback"
    ambiguity_flags: tuple[str, ...]
    engine_outcome: str               # ALLOWED | BLOCKED (unchanged by this layer)
    rationale: str
    annotations: tuple[str, ...] = ()
    latency_ms: float = 0.0
    confidence: float | None = None
    model: str = OFFLINE_SOURCE
    error: str | None = None

    @property
    def is_live(self) -> bool:
        return self.source == LIVE_SOURCE

    @property
    def escalates(self) -> bool:
        return self.triage == ESCALATE

    def summary(self) -> str:
        """One-line, payload-free string for the UI and the audit trail."""
        detail = self.model if self.is_live else "no model call"
        flags = ", ".join(self.ambiguity_flags) or "none"
        line = f"Jev preflight [{self.triage} · {self.source} · {detail}] — ambiguous: {flags}"
        if self.annotations:
            line += " — " + " | ".join(self.annotations)
        if self.error:
            line += f" (fallback: {self.error})"
        return line


# ─────────────────────────────────────────────────────────────────────────────
# Ambiguity detection — deterministic, always available offline
# ─────────────────────────────────────────────────────────────────────────────

def engine_outcome(result: Any) -> str:
    """Normalize a PolicyResult or a standalone CheckResult to ALLOWED/BLOCKED."""
    outcome = getattr(result, "outcome", None)
    if outcome in ("ALLOWED", "BLOCKED"):
        return outcome
    if getattr(result, "blocked", None) is True:
        return "BLOCKED"
    return "ALLOWED"


def _vendor_resolves(vendor_id: Any) -> bool:
    if not isinstance(vendor_id, str) or not vendor_id:
        return False
    if vendor_id in VENDOR_REGISTRY:
        return True
    return vendor_id.strip().lower() in BLOCKED_PLATFORMS


def _justification_owed(result: Any) -> bool:
    """A reason is owed but absent, judged from the tool/purpose/sensitivity.

    The trials flagged this as the fix for bare `missing_justification`:
    a physician reading a standard record owes no written reason, while a
    vendor send or a SENSITIVE-tier read does.
    """
    if (getattr(result, "justification", "") or "").strip():
        return False
    tool = getattr(result, "tool", "")
    if tool in _EGRESS_OR_WRITE_TOOLS:
        return True
    patient_id = getattr(result, "patient_id", None)
    patient = PATIENT_DB.get(patient_id) if patient_id else None
    if patient is not None and patient.sensitivity in _SENSITIVE_TIERS:
        return True
    return False


def _phi_pattern_gap(result: Any) -> bool:
    """PHI cues the regex cannot confirm, or sees under the block threshold."""
    detection = getattr(result, "phi", None)
    if detection is not None and getattr(detection, "phi_found", False):
        if not should_block(detection):
            return True
    elif detection is None:
        # Standalone CheckResult shape: a scalar risk with no match detail.
        risk = float(getattr(result, "risk_score", 0.0) or 0.0)
        if 0.0 < risk < 0.60 and getattr(result, "phi_types", None):
            return True
    return bool(getattr(result, "phi_narrative_cues", False))


def ambiguity_flags(result: Any, *, known_tools: frozenset[str] = KNOWN_TOOLS) -> tuple[str, ...]:
    """Deterministic ambiguity signals for one engine result. Payload-free."""
    flags: list[str] = []
    tool = getattr(result, "tool", "")
    if tool not in known_tools:
        flags.append("novel_tool")
    if tool == "send_data_to_vendor" and not _vendor_resolves(getattr(result, "vendor_id", None)):
        flags.append("unknown_vendor")
    if _justification_owed(result):
        flags.append("justification_owed")
    if _phi_pattern_gap(result):
        flags.append("phi_pattern_gap")
    return tuple(flags)


# ─────────────────────────────────────────────────────────────────────────────
# Triage composition — the lane is always decided here, in code
# ─────────────────────────────────────────────────────────────────────────────

def _lane(result: Any, flags: tuple[str, ...]) -> tuple[str, str]:
    """The if statement. The model never overrides this."""
    outcome = engine_outcome(result)
    if outcome == "BLOCKED":
        return (
            ESCALATE,
            "Engine blocked; the advisory confirms escalation rather than attempting "
            "to overturn a policy decision.",
        )
    if "phi_pattern_gap" in flags:
        return (
            DEIDENTIFY,
            "Unconfirmed PHI pattern — redact before any egress, then re-evaluate.",
        )
    return (
        ESCALATE,
        "Ambiguous request — route to human review rather than allow on an "
        "unresolved signal.",
    )


def _annotations(checks_run: dict[str, Verdict]) -> tuple[str, ...]:
    return tuple(f"{name}: {verdict.summary()}" for name, verdict in checks_run.items())


def preflight(
    result: Any,
    *,
    allow_network: bool | None = None,
    key_path: str | None = None,
    ask: Callable[..., Any] = ask_jev,
) -> PreflightAdvisory | None:
    """Return an advisory for an ambiguous result, else None.

    None means "the engine resolved this unambiguously" — the caller should
    do nothing further. The lane comes from `_lane`; the model (or the
    offline stand-in) only annotates. No transport failure raises.
    """
    flags = ambiguity_flags(result)
    if not flags:
        return None
    live = network_enabled(allow_network)
    triage, rationale = _lane(result, flags)

    checks_run: dict[str, Verdict] = {}
    for flag, check in _CHECK_FOR_FLAG.items():
        if flag not in flags:
            continue
        field_name = "vendor_id" if check is VENDOR_CHECK else "tool"
        checks_run[check.name] = run_check(
            check,
            {field_name: getattr(result, field_name, "") or ""},
            allow_network=live,
            key_path=key_path,
            ask=ask,
        )

    live_ran = any(verdict.source == "jev" for verdict in checks_run.values())
    confidences = [v.confidence for v in checks_run.values() if v.confidence is not None]
    errors = [v.error for v in checks_run.values() if v.error]
    return PreflightAdvisory(
        triage=triage,
        source=LIVE_SOURCE if live_ran else OFFLINE_SOURCE,
        ambiguity_flags=flags,
        engine_outcome=engine_outcome(result),
        rationale=rationale,
        annotations=_annotations(checks_run),
        latency_ms=sum(v.latency_ms for v in checks_run.values()),
        confidence=min(confidences) if confidences else None,
        model=LIVE_SOURCE if live_ran else OFFLINE_SOURCE,
        error="; ".join(errors) if errors else None,
    )


def make_adviser(
    *,
    allow_network: bool | None = None,
    key_path: str | None = None,
    ask: Callable[..., Any] = ask_jev,
) -> Callable[[Any], PreflightAdvisory | None]:
    """Bind a preflight call into the `adviser` hook on policy_engine.evaluate."""

    def _adviser(result: Any) -> PreflightAdvisory | None:
        return preflight(result, allow_network=allow_network, key_path=key_path, ask=ask)

    return _adviser
