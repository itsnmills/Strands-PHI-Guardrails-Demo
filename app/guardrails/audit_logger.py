"""
app/guardrails/audit_logger.py
──────────────────────────────
Tamper-evident structured HIPAA audit logging.

HIPAA §164.312(b) requires audit controls — hardware, software, and
procedural mechanisms to record and examine activity in systems that
contain or use electronic PHI (ePHI).

This module produces structured audit events compatible with:
  - SIEM ingestion (Splunk, Sentinel, CrowdStrike Falcon LogScale)
  - HIPAA audit log requirements
  - 45 CFR Part 164 Access Control standards

Tamper evidence: every event is sealed into an HMAC-SHA256 hash chain.
Each event carries the hash of its predecessor plus an HMAC over the
canonical serialization of its own contents, so any modification,
deletion, or reordering of history is detectable via verify_chain().

In production: events would be append-only (S3 object lock / WORM
storage), the signing key would live in a KMS/HSM, and the stream
would ship to a centralized SIEM with 6-year retention.
"""

import datetime
import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass, field, asdict
from typing import Literal, Any


EventOutcome = Literal["SUCCESS", "BLOCKED", "WARNING", "ERROR"]

EventCategory = Literal[
    "ACCESS",        # PHI record accessed
    "DISCLOSURE",    # PHI sent externally
    "MODIFICATION",  # PHI or record changed
    "AUTHENTICATION",# Login / role assumption
    "POLICY_EVAL",   # Guardrail/policy evaluation
    "AUDIT_VIEW",    # Audit log itself was read
    "BREAK_GLASS",   # Emergency override granted (post-hoc review required)
]


@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    category: EventCategory
    outcome: EventOutcome
    actor_role: str
    actor_id: str                    # simulated user ID
    tool_name: str
    action_description: str
    patient_id: str | None
    vendor_id: str | None
    policy_rule_triggered: str | None
    denial_reason: str | None
    phi_types_detected: list[str]
    risk_score: float
    inputs_sanitized: dict[str, Any]  # PHI-masked copy of inputs
    purpose_of_use: str | None
    justification: str | None
    # ── Tamper-evident chain fields ─────────────────────────────
    prev_hash: str = ""              # HMAC of the previous event ("GENESIS" anchor for first)
    entry_hash: str = ""             # HMAC over canonical contents + prev_hash

    def to_dict(self) -> dict:
        return asdict(self)

    def display_line(self) -> str:
        marker = "🚫" if self.outcome == "BLOCKED" else "✅" if self.outcome == "SUCCESS" else "⚠️"
        return f"{marker} [{self.timestamp}] {self.category} | {self.tool_name} | {self.actor_role} | {self.outcome}"


class AuditLogger:
    """
    Session-scoped, tamper-evident audit log.

    Events form an HMAC-SHA256 chain: entry_hash = HMAC(key, prev_hash + canonical(event)).
    The signing key is generated per-logger (in production: KMS/HSM-held key shared
    by the append-only writer). verify_chain() walks the chain and reports the first
    event whose contents or linkage were altered.
    """

    GENESIS = "0" * 64

    def __init__(self, signing_key: bytes | None = None):
        self._signing_key = signing_key or secrets.token_bytes(32)
        self._events: list[AuditEvent] = []
        self._prev_hash = self.GENESIS

    # ── Chain internals ─────────────────────────────────────────

    def _canonical(self, event_dict: dict) -> str:
        """Stable serialization: sorted keys, no whitespace, JSON-safe values."""
        return json.dumps(event_dict, sort_keys=True, separators=(",", ":"), default=str)

    def _entry_payload(self, event: AuditEvent) -> dict:
        return {k: v for k, v in asdict(event).items() if k != "entry_hash"}

    def _compute_entry_hash(self, payload: dict, prev_hash: str) -> str:
        material = (prev_hash + self._canonical(payload)).encode()
        return hmac.new(self._signing_key, material, hashlib.sha256).hexdigest()

    # ── Event creation ──────────────────────────────────────────

    def log(
        self,
        *,
        category: EventCategory,
        outcome: EventOutcome,
        actor_role: str,
        actor_id: str,
        tool_name: str,
        action_description: str,
        patient_id: str | None = None,
        vendor_id: str | None = None,
        policy_rule_triggered: str | None = None,
        denial_reason: str | None = None,
        phi_types_detected: list[str] | None = None,
        risk_score: float = 0.0,
        inputs_sanitized: dict | None = None,
        purpose_of_use: str | None = None,
        justification: str | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=str(uuid.uuid4())[:8],
            timestamp=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            category=category,
            outcome=outcome,
            actor_role=actor_role,
            actor_id=actor_id,
            tool_name=tool_name,
            action_description=action_description,
            patient_id=patient_id,
            vendor_id=vendor_id,
            policy_rule_triggered=policy_rule_triggered,
            denial_reason=denial_reason,
            phi_types_detected=phi_types_detected or [],
            risk_score=risk_score,
            inputs_sanitized=inputs_sanitized or {},
            purpose_of_use=purpose_of_use,
            justification=justification,
        )
        event.prev_hash = self._prev_hash
        event.entry_hash = self._compute_entry_hash(self._entry_payload(event), self._prev_hash)
        self._prev_hash = event.entry_hash
        self._events.append(event)
        return event

    # ── Verification ────────────────────────────────────────────

    def verify_chain(self) -> dict:
        """
        Walk the hash chain and verify every event's integrity and linkage.
        Returns {"intact": bool, "broken_at": event_id|None, "events_checked": int, "chain_head": str}.
        """
        prev = self.GENESIS
        for event in self._events:
            expected = self._compute_entry_hash(self._entry_payload(event), prev)
            if event.prev_hash != prev or event.entry_hash != expected:
                return {
                    "intact": False,
                    "broken_at": event.event_id,
                    "events_checked": self._events.index(event) + 1,
                    "chain_head": prev,
                }
            prev = event.entry_hash
        return {
            "intact": True,
            "broken_at": None,
            "events_checked": len(self._events),
            "chain_head": self._prev_hash,
        }

    @property
    def chain_head(self) -> str:
        """Hash of the most recent event — an anchor for external notarization."""
        return self._prev_hash

    # ── Views ───────────────────────────────────────────────────

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    @property
    def blocked_events(self) -> list[AuditEvent]:
        return [e for e in self._events if e.outcome == "BLOCKED"]

    @property
    def allowed_events(self) -> list[AuditEvent]:
        return [e for e in self._events if e.outcome == "SUCCESS"]

    @property
    def warning_events(self) -> list[AuditEvent]:
        return [e for e in self._events if e.outcome == "WARNING"]

    def events_by_category(self, category: str) -> list[AuditEvent]:
        return [e for e in self._events if e.category == category]

    def clear(self):
        self._events.clear()
        self._prev_hash = self.GENESIS

    def violation_count(self) -> int:
        return len(self.blocked_events)

    def compliance_summary(self) -> dict:
        total = len(self._events)
        blocked = len(self.blocked_events)
        chain = self.verify_chain()
        return {
            "total_events": total,
            "blocked_events": blocked,
            "allowed_events": total - blocked,
            "compliance_rate": f"{((total - blocked) / total * 100):.1f}%" if total > 0 else "N/A",
            "policy_violations": blocked,
            "audit_chain_intact": chain["intact"],
            "chain_head": chain["chain_head"],
        }
