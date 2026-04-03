"""
app/guardrails/audit_logger.py
───────────────────────────────
Structured HIPAA audit logging.

HIPAA §164.312(b) requires audit controls — hardware, software, and
procedural mechanisms to record and examine activity in systems that
contain or use electronic PHI (ePHI).

This module produces structured audit events compatible with:
  - SIEM ingestion (Splunk, Sentinel, CrowdStrike Falcon LogScale)
  - HIPAA audit log requirements
  - 45 CFR Part 164 Access Control standards

In production: events would be append-only, tamper-evident (hash chain),
and shipped to a centralized SIEM with 6-year retention.
"""

import datetime
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

    def to_dict(self) -> dict:
        return asdict(self)

    def display_line(self) -> str:
        marker = "🚫" if self.outcome == "BLOCKED" else "✅" if self.outcome == "SUCCESS" else "⚠️"
        return f"{marker} [{self.timestamp}] {self.category} | {self.tool_name} | {self.actor_role} | {self.outcome}"


class AuditLogger:
    """
    Session-scoped audit log. In production, this writes to an immutable
    append-only store (S3 with object lock, WORM storage, etc.)
    """

    def __init__(self):
        self._events: list[AuditEvent] = []

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
            timestamp=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
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
        self._events.append(event)
        return event

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    @property
    def blocked_events(self) -> list[AuditEvent]:
        return [e for e in self._events if e.outcome == "BLOCKED"]

    @property
    def allowed_events(self) -> list[AuditEvent]:
        return [e for e in self._events if e.outcome == "SUCCESS"]

    def clear(self):
        self._events.clear()

    def violation_count(self) -> int:
        return len(self.blocked_events)

    def compliance_summary(self) -> dict:
        total = len(self._events)
        blocked = len(self.blocked_events)
        return {
            "total_events": total,
            "blocked_events": blocked,
            "allowed_events": total - blocked,
            "compliance_rate": f"{((total - blocked) / total * 100):.1f}%" if total > 0 else "N/A",
            "policy_violations": blocked,
        }
