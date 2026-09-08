"""
app/compliance/disclosures.py
────────────────────────────
Accounting of disclosures — 45 CFR §164.528.

An individual has the right to receive an accounting of disclosures of
their PHI made in the six years prior to the request date (excluding
treatment, payment, and operations disclosures made under authorizations
or exceptions). Practically: when a compliance officer or a patient asks
"who saw my data and where did it go?", the covered entity must produce
this report FROM THE AUDIT TRAIL — not from memory.

This module renders that report from the hash-chained audit log:

  - DISCLOSURE events  → PHI sent to external vendors
  - BREAK_GLASS events → emergency override grants (always reportable:
    they are disclosures outside the routine TPO lane and flagged for
    post-hoc review by design)

Nothing here interprets law; the module produces the *evidence* the
privacy office needs, straight from the tamper-evident log.
"""

import csv
import io
from dataclasses import dataclass, field

from app.guardrails.audit_logger import AuditLogger

REPORTABLE_CATEGORIES = ("DISCLOSURE", "BREAK_GLASS")


@dataclass
class DisclosureRow:
    timestamp: str
    event_id: str
    category: str
    patient_id: str | None
    recipient: str             # vendor id/name or "emergency access"
    purpose: str | None
    actor_role: str
    actor_id: str
    description: str
    outcome: str


@dataclass
class DisclosureReport:
    rows: list[DisclosureRow] = field(default_factory=list)
    excluded_events: int = 0       # events reviewed but not reportable under §164.528
    chain_intact: bool = True

    def to_text(self) -> str:
        """Fixed-width rendering suitable for the privacy office."""
        if not self.rows:
            return "No reportable disclosures recorded."
        lines = [
            "ACCOUNTING OF DISCLOSURES — 45 CFR §164.528",
            f"Reportable events: {len(self.rows)} · non-reportable reviewed: {self.excluded_events} · "
            f"audit chain {'INTACT' if self.chain_intact else 'COMPROMISED'}",
            "─" * 132,
            f"{'TIMESTAMP':<21}{'PATIENT':<9}{'RECIPIENT':<22}{'PURPOSE':<12}{'ACTOR':<26}{'OUTCOME':<10}EVENT",
            "─" * 132,
        ]
        for r in self.rows:
            actor = f"{r.actor_role}/{r.actor_id}"
            lines.append(
                f"{r.timestamp:<21}{r.patient_id or '—':<9}{r.recipient:<22}{r.purpose or '—':<12}"
                f"{actor:<26}{r.outcome:<10}{r.description[:44]}"
            )
        return "\n".join(lines)

    def to_csv(self) -> bytes:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["timestamp", "event_id", "category", "patient_id", "recipient",
                    "purpose_of_use", "actor_role", "actor_id", "description", "outcome"])
        for r in self.rows:
            w.writerow([r.timestamp, r.event_id, r.category, r.patient_id, r.recipient,
                        r.purpose, r.actor_role, r.actor_id, r.description, r.outcome])
        return buf.getvalue().encode()

    def summary(self) -> dict:
        by_vendor: dict[str, int] = {}
        by_patient: dict[str, int] = {}
        for r in self.rows:
            by_vendor[r.recipient] = by_vendor.get(r.recipient, 0) + 1
            if r.patient_id:
                by_patient[r.patient_id] = by_patient.get(r.patient_id, 0) + 1
        return {
            "reportable_disclosures": len(self.rows),
            "by_recipient": by_vendor,
            "by_patient": by_patient,
            "excluded_events": self.excluded_events,
            "chain_intact": self.chain_intact,
        }


def disclosure_report(logger: AuditLogger) -> DisclosureReport:
    """
    Render the §164.528 accounting from the audit chain.
    Reportable: DISCLOSURE (external sends) + BREAK_GLASS (emergency overrides).
    Everything else (ACCESS under TPO, policy evals, audit views) is reviewed
    and counted as excluded.
    """
    rows: list[DisclosureRow] = []
    excluded = 0
    for e in logger.events:
        if e.category not in REPORTABLE_CATEGORIES:
            excluded += 1
            continue
        if e.category == "BREAK_GLASS":
            recipient = "emergency access (break-glass)"
        elif e.vendor_id:
            vendor_note = f"{e.vendor_id} (blocked platform)" if "consumer platform" in (e.denial_reason or "") else e.vendor_id
            recipient = vendor_note
        else:
            recipient = e.tool_name
        rows.append(DisclosureRow(
            timestamp=e.timestamp,
            event_id=e.event_id,
            category=e.category,
            patient_id=e.patient_id,
            recipient=recipient,
            purpose=e.purpose_of_use,
            actor_role=e.actor_role,
            actor_id=e.actor_id,
            description=e.action_description,
            outcome=e.outcome,
        ))
    return DisclosureReport(
        rows=rows,
        excluded_events=excluded,
        chain_intact=logger.verify_chain()["intact"],
    )
