"""
app/policies/break_glass.py
───────────────────────────
Break-glass emergency access — the controlled exception path.

Real emergency departments cannot wait for paperwork: a crashing
patient needs their record NOW. HIPAA handles this with "break-glass"
overrides: access is granted under an explicit, recorded justification,
then subjected to MANDATORY post-hoc review (§164.528 accounting of
disclosures).

Design (mirrors Epic/Cerner break-glass):
  - Grant is scoped to ONE patient + ONE role, never blanket
  - Grant carries a required free-text reason (the audit trail is the point)
  - Grant expires (default 15 minutes) — no standing elevated access
  - Every grant and every use is a flagged BREAK_GLASS audit event
  - Grants land in a post-hoc review queue — compliance reviews them after
    the emergency; misuse here is the #1 real-world insider-risk signal

NOT the same as "access denied, try harder": break-glass is a
first-class policy object with its own audit category.
"""

import secrets
import time as _time
from dataclasses import dataclass, field
from typing import Literal

from app.guardrails.audit_logger import AuditLogger

MIN_REASON_CHARS = 20  # "patient crashing" is not a justification


@dataclass
class BreakGlassGrant:
    token: str
    role: str
    patient_id: str
    reason: str
    granted_at: float            # epoch seconds
    expires_at: float            # epoch seconds

    def minutes_remaining(self, now: float | None = None) -> float:
        now = now if now is not None else _time.time()
        return max(0.0, (self.expires_at - now) / 60.0)

    def is_active(self, now: float | None = None) -> bool:
        now = now if now is not None else _time.time()
        return now < self.expires_at


@dataclass
class BreakGlassRegistry:
    """
    Session-scoped registry of emergency grants.
    Optionally wired to an AuditLogger — every grant/revoke/use is recorded
    under the BREAK_GLASS category for mandatory post-hoc review.
    """
    ttl_minutes: float = 15.0
    audit: AuditLogger | None = None
    _grants: dict[str, BreakGlassGrant] = field(default_factory=dict)  # key: f"{role}:{patient_id}"

    # ── Grant lifecycle ─────────────────────────────────────────

    def grant(self, role: str, patient_id: str, reason: str, actor_id: str = "session-user",
              now: float | None = None) -> BreakGlassGrant:
        now = now if now is not None else _time.time()
        reason = (reason or "").strip()
        if len(reason) < MIN_REASON_CHARS:
            raise ValueError(
                f"Break-glass requires a substantive justification "
                f"(min {MIN_REASON_CHARS} chars) — the reason is the audit trail."
            )
        key = f"{role}:{patient_id}"
        g = BreakGlassGrant(
            token=secrets.token_hex(4),
            role=role,
            patient_id=patient_id,
            reason=reason,
            granted_at=now,
            expires_at=now + self.ttl_minutes * 60.0,
        )
        self._grants[key] = g
        if self.audit:
            self.audit.log(
                category="BREAK_GLASS",
                outcome="WARNING",
                actor_role=role,
                actor_id=actor_id,
                tool_name="break_glass_grant",
                action_description=(
                    f"EMERGENCY OVERRIDE granted for {patient_id} — expires in {self.ttl_minutes:.0f}m. "
                    f"Reason: {reason}"
                ),
                patient_id=patient_id,
                policy_rule_triggered="Break-Glass: Emergency Override",
                inputs_sanitized={"reason": reason, "token": g.token, "ttl_minutes": self.ttl_minutes},
                purpose_of_use="TREATMENT",
                justification=reason,
            )
        return g

    def revoke(self, role: str, patient_id: str, actor_id: str = "session-user"):
        key = f"{role}:{patient_id}"
        g = self._grants.pop(key, None)
        if g and self.audit:
            self.audit.log(
                category="BREAK_GLASS",
                outcome="SUCCESS",
                actor_role=role,
                actor_id=actor_id,
                tool_name="break_glass_revoke",
                action_description=f"Emergency override for {patient_id} revoked (token {g.token})",
                patient_id=patient_id,
                policy_rule_triggered="Break-Glass: Override Revoked",
            )
        return g

    def active_grant(self, role: str, patient_id: str, now: float | None = None) -> BreakGlassGrant | None:
        now = now if now is not None else _time.time()
        g = self._grants.get(f"{role}:{patient_id}")
        if g and g.is_active(now):
            return g
        return None

    # ── Review queues ───────────────────────────────────────────

    def active_grants(self, now: float | None = None) -> list[BreakGlassGrant]:
        now = now if now is not None else _time.time()
        return [g for g in self._grants.values() if g.is_active(now)]

    def pending_review(self) -> list[BreakGlassGrant]:
        """Every grant ever issued lands here — compliance reviews after the fact."""
        return list(self._grants.values())
