"""
app/guardrails/session_monitor.py
─────────────────────────────────
Rolling-window behavioral monitor that gives the Minimum Necessary
standard (45 CFR §164.502(b)) real enforcement teeth.

Static policy checks validate a single request in isolation. This
module tracks what the session has ALREADY done and flags usage
patterns that a single request can never reveal:

  - record-access velocity (chart snooping / record stubbing)
  - outbound send velocity (bulk exfiltration)

Verdicts follow a warn-then-block escalation:
  - below budget          → "ok"
  - at budget             → "warn"  (anomaly recorded, access continues)
  - at 2× budget          → "block" (minimum-necessary violation, denied)

Every anomaly is auditable via `anomalies` — in production these feed
the insider-threat program (Insider Risk / UEBA tooling).

Window, budgets, and escalation thresholds are deliberately visible
in the module so interviewers can trace the enforcement story.
"""

import time
from dataclasses import dataclass, field

from app.policies.rbac import get_policy, ClinicalRole

WARN_MULTIPLIER = 1.0     # warn when window usage reaches the budget
BLOCK_MULTIPLIER = 2.0    # block at 2× budget


@dataclass
class Anomaly:
    ts: float
    kind: str                 # "velocity_query" | "velocity_send"
    role: str
    detail: str
    verdict: str              # "warn" | "block"
    count: int
    budget: int


@dataclass
class SessionMonitor:
    window_seconds: float = 300.0   # 5-minute rolling window
    _accesses: list[tuple[float, str, str]] = field(default_factory=list)  # (ts, role, patient_id)
    _sends: list[tuple[float, str, str]] = field(default_factory=list)     # (ts, role, vendor_id)
    _anomalies: list[Anomaly] = field(default_factory=list)

    # ── Internals ───────────────────────────────────────────────

    def _prune(self, now: float):
        cutoff = now - self.window_seconds
        self._accesses = [t for t in self._accesses if t[0] >= cutoff]
        self._sends = [t for t in self._sends if t[0] >= cutoff]

    def _verdict(self, count: int, budget: int) -> tuple[str, str | None]:
        if budget <= 0:
            return "ok", None
        if count >= budget * BLOCK_MULTIPLIER:
            return "block", None
        if count >= budget * WARN_MULTIPLIER:
            return "warn", None
        return "ok", None

    # ── Public API ──────────────────────────────────────────────

    def check_query(self, role: ClinicalRole, patient_id: str | None, now: float | None = None) -> tuple[str, str]:
        """Record a record access and return (verdict, message). verdict ∈ {ok, warn, block}."""
        now = now if now is not None else time.time()
        self._prune(now)
        budget = get_policy(role).max_records_per_query
        if not patient_id or budget <= 0:
            return "ok", ""
        self._accesses.append((now, role, patient_id))
        count = len([t for t in self._accesses if t[1] == role])
        verdict, _ = self._verdict(count, budget)
        if verdict == "ok":
            return "ok", ""
        detail = (
            f"{count} record accesses in the last {self.window_seconds/60:.0f}m "
            f"(budget for '{role}': {budget}, block at {budget * BLOCK_MULTIPLIER:.0f})"
        )
        self._anomalies.append(Anomaly(now, "velocity_query", role, detail, verdict, count, budget))
        return verdict, detail

    def check_send(self, role: ClinicalRole, vendor_id: str | None, now: float | None = None) -> tuple[str, str]:
        """Record an outbound send and return (verdict, message)."""
        now = now if now is not None else time.time()
        self._prune(now)
        budget = get_policy(role).max_records_per_query  # sends share the access budget
        if not vendor_id or budget <= 0:
            return "ok", ""
        self._sends.append((now, role, vendor_id))
        count = len([t for t in self._sends if t[1] == role])
        verdict, _ = self._verdict(count, budget)
        if verdict == "ok":
            return "ok", ""
        detail = (
            f"{count} external transmissions in the last {self.window_seconds/60:.0f}m "
            f"(budget for '{role}': {budget}, block at {budget * BLOCK_MULTIPLIER:.0f})"
        )
        self._anomalies.append(Anomaly(now, "velocity_send", role, detail, verdict, count, budget))
        return verdict, detail

    @property
    def anomalies(self) -> list[Anomaly]:
        return list(self._anomalies)

    @property
    def anomaly_count(self) -> int:
        return len(self._anomalies)

    def reset(self):
        self._accesses.clear()
        self._sends.clear()
        self._anomalies.clear()
