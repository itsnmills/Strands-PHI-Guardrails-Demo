"""
app/policies/purpose_of_use.py
───────────────────────────────
Purpose-of-Use (PoU) validation.

HIPAA requires that PHI access be for a valid purpose and that only
the minimum necessary data is disclosed. This module enforces:

  1. That a stated purpose is provided before PHI is accessed
  2. That the stated purpose is valid for the requesting role
  3. That the purpose maps to an allowed data scope

Real-world equivalent: 'Break-glass' audit reasons, HIPAA access reason codes,
and HL7 FHIR purpose-of-use value sets (Treatment, Payment, Operations, etc.)
"""

from dataclasses import dataclass
from typing import Literal

PurposeCode = Literal[
    "TREATMENT",        # Direct patient care — broadest access
    "PAYMENT",          # Billing and claims processing
    "OPERATIONS",       # Healthcare operations (quality, training)
    "RESEARCH",         # IRB-approved research
    "LEGAL",            # Subpoena, court order
    "PUBLIC_HEALTH",    # Required public health reporting
    "HANDOFF",          # Shift handoff / care transition
    "AUDIT",            # Compliance audit
]

PURPOSE_DISPLAY: dict[PurposeCode, str] = {
    "TREATMENT": "Treatment — Direct Patient Care",
    "PAYMENT": "Payment — Billing & Claims",
    "OPERATIONS": "Healthcare Operations",
    "RESEARCH": "IRB-Approved Research",
    "LEGAL": "Legal / Court Order",
    "PUBLIC_HEALTH": "Public Health Reporting",
    "HANDOFF": "Care Transition / Shift Handoff",
    "AUDIT": "Compliance Audit",
}

PURPOSE_DESCRIPTIONS: dict[PurposeCode, str] = {
    "TREATMENT": "Accessing PHI to provide, coordinate, or manage treatment for a patient currently under your care.",
    "PAYMENT": "Processing claims, verifying coverage, or obtaining payment for services rendered.",
    "OPERATIONS": "Quality improvement, staff training, or other healthcare operations activities.",
    "RESEARCH": "IRB-approved study. De-identified data only unless IRB waiver is on file.",
    "LEGAL": "Response to valid subpoena or court order. Legal team must be notified.",
    "PUBLIC_HEALTH": "Mandatory reporting to public health authorities (e.g., infectious disease).",
    "HANDOFF": "Transferring care to another provider. Minimum necessary summary only.",
    "AUDIT": "Reviewing audit logs for compliance purposes. No PHI access granted.",
}


@dataclass
class PurposePolicy:
    purpose: PurposeCode
    phi_access_allowed: bool
    sensitive_access_allowed: bool
    restricted_access_allowed: bool
    requires_justification_text: bool
    allowed_roles: list[str]          # which roles may use this purpose
    data_scope_note: str


PURPOSE_POLICIES: dict[PurposeCode, PurposePolicy] = {
    "TREATMENT": PurposePolicy(
        purpose="TREATMENT",
        phi_access_allowed=True,
        sensitive_access_allowed=True,
        restricted_access_allowed=True,   # with documented treating relationship
        requires_justification_text=False,
        allowed_roles=["physician", "nurse"],
        data_scope_note="Full record for treating providers with documented patient relationship.",
    ),
    "PAYMENT": PurposePolicy(
        purpose="PAYMENT",
        phi_access_allowed=True,
        sensitive_access_allowed=False,
        restricted_access_allowed=False,
        requires_justification_text=True,
        allowed_roles=["billing_staff", "physician"],
        data_scope_note="Billing data only: diagnosis codes, procedure codes, dates of service. NO clinical notes.",
    ),
    "OPERATIONS": PurposePolicy(
        purpose="OPERATIONS",
        phi_access_allowed=True,
        sensitive_access_allowed=False,
        restricted_access_allowed=False,
        requires_justification_text=True,
        allowed_roles=["physician", "nurse", "it_admin"],
        data_scope_note="De-identified or aggregate data preferred. Access to identifiable data requires approval.",
    ),
    "RESEARCH": PurposePolicy(
        purpose="RESEARCH",
        phi_access_allowed=False,
        sensitive_access_allowed=False,
        restricted_access_allowed=False,
        requires_justification_text=True,
        allowed_roles=["researcher"],
        data_scope_note="De-identified data only under IRB protocol. Full PHI requires IRB waiver.",
    ),
    "LEGAL": PurposePolicy(
        purpose="LEGAL",
        phi_access_allowed=True,
        sensitive_access_allowed=True,
        restricted_access_allowed=True,
        requires_justification_text=True,
        allowed_roles=["physician", "it_admin"],
        data_scope_note="Scope defined by legal instrument. Minimum necessary. Legal team must be cc'd.",
    ),
    "PUBLIC_HEALTH": PurposePolicy(
        purpose="PUBLIC_HEALTH",
        phi_access_allowed=True,
        sensitive_access_allowed=True,
        restricted_access_allowed=False,
        requires_justification_text=True,
        allowed_roles=["physician", "nurse"],
        data_scope_note="Only data required for reportable condition. Name + diagnosis typically sufficient.",
    ),
    "HANDOFF": PurposePolicy(
        purpose="HANDOFF",
        phi_access_allowed=True,
        sensitive_access_allowed=True,
        restricted_access_allowed=False,   # psych handoffs require separate process
        requires_justification_text=False,
        allowed_roles=["physician", "nurse"],
        data_scope_note="Active problems, medications, pending orders. Minimum necessary for safe care transfer.",
    ),
    "AUDIT": PurposePolicy(
        purpose="AUDIT",
        phi_access_allowed=False,
        sensitive_access_allowed=False,
        restricted_access_allowed=False,
        requires_justification_text=True,
        allowed_roles=["it_admin", "external_auditor"],
        data_scope_note="Audit logs only. PHI must be masked in audit output.",
    ),
}


def validate_purpose(
    role: str,
    purpose: PurposeCode,
    justification: str = "",
) -> tuple[bool, str]:
    """
    Returns (valid, denial_reason).
    Checks: (1) role may use this purpose, (2) justification provided if required.
    """
    if purpose not in PURPOSE_POLICIES:
        return False, f"Unknown purpose code: '{purpose}'."

    policy = PURPOSE_POLICIES[purpose]

    if role not in policy.allowed_roles:
        return False, (
            f"Role '{role}' is not authorized to use purpose '{purpose}'. "
            f"Authorized roles: {policy.allowed_roles}."
        )

    if policy.requires_justification_text and not justification.strip():
        return False, (
            f"Purpose '{purpose}' requires a written justification. "
            "Provide a brief explanation of why this access is needed."
        )

    return True, ""
