"""
app/policies/rbac.py
─────────────────────
Role-Based Access Control (RBAC) policy matrix for clinical roles.

This is policy-as-code: access rules are explicit, versioned, and auditable.
In production this would integrate with an Identity Provider (e.g. Okta, Azure AD)
and be enforced at the API/service layer, not just the AI agent layer.

Roles modeled after real hospital job families:
  - physician         : treating providers — broad clinical access
  - nurse             : bedside care — access scoped to assigned patients
  - billing_staff     : revenue cycle — billing data, no clinical notes
  - researcher        : IRB-approved studies — de-identified data only
  - it_admin          : system administration — no PHI access
  - external_auditor  : compliance review — audit logs only
"""

from dataclasses import dataclass
from typing import Literal

ClinicalRole = Literal[
    "physician",
    "nurse",
    "billing_staff",
    "researcher",
    "it_admin",
    "external_auditor",
]

ROLE_DISPLAY = {
    "physician": "Physician (Treating Provider)",
    "nurse": "Registered Nurse",
    "billing_staff": "Billing / Revenue Cycle Staff",
    "researcher": "IRB-Approved Researcher",
    "it_admin": "IT Administrator",
    "external_auditor": "External Compliance Auditor",
}

ROLE_DESCRIPTIONS = {
    "physician": "Full clinical access to assigned patients. Can view PHI, write notes, order tests.",
    "nurse": "Access to assigned-floor patients. Can view clinical summaries and log nursing notes.",
    "billing_staff": "Revenue cycle access only. Can view billing codes and claims data — NOT clinical notes or diagnoses.",
    "researcher": "De-identified data only under IRB approval. Cannot view any direct identifiers.",
    "it_admin": "System configuration only. Cannot access PHI. Can view system audit logs.",
    "external_auditor": "Read-only access to audit logs for compliance review. No PHI access.",
}


@dataclass
class RolePolicy:
    role: ClinicalRole
    can_query_records: bool
    can_view_sensitive: bool         # SENSITIVE tier records (substance use, HIV)
    can_view_restricted: bool        # RESTRICTED tier records (psych, genetic)
    can_send_to_vendors: bool
    can_send_sensitive_externally: bool
    can_log_notes: bool
    can_view_audit_log: bool
    max_records_per_query: int       # minimum necessary enforcement
    requires_patient_relationship: bool  # must have documented care relationship
    requires_purpose_of_use: bool    # must declare reason before access


ROLE_POLICIES: dict[ClinicalRole, RolePolicy] = {
    "physician": RolePolicy(
        role="physician",
        can_query_records=True,
        can_view_sensitive=True,
        can_view_restricted=True,
        can_send_to_vendors=True,
        can_send_sensitive_externally=False,  # requires special auth even for physicians
        can_log_notes=True,
        can_view_audit_log=False,
        max_records_per_query=5,
        requires_patient_relationship=True,
        requires_purpose_of_use=True,
    ),
    "nurse": RolePolicy(
        role="nurse",
        can_query_records=True,
        can_view_sensitive=True,
        can_view_restricted=False,   # psych records require separate authorization
        can_send_to_vendors=False,
        can_send_sensitive_externally=False,
        can_log_notes=True,
        can_view_audit_log=False,
        max_records_per_query=3,
        requires_patient_relationship=True,
        requires_purpose_of_use=True,
    ),
    "billing_staff": RolePolicy(
        role="billing_staff",
        can_query_records=True,      # billing codes only — enforced in tool layer
        can_view_sensitive=False,
        can_view_restricted=False,
        can_send_to_vendors=True,    # to billing processors only
        can_send_sensitive_externally=False,
        can_log_notes=False,
        can_view_audit_log=False,
        max_records_per_query=10,   # can batch claims
        requires_patient_relationship=False,
        requires_purpose_of_use=True,
    ),
    "researcher": RolePolicy(
        role="researcher",
        can_query_records=False,     # must use generate_summary (de-identified)
        can_view_sensitive=False,
        can_view_restricted=False,
        can_send_to_vendors=False,
        can_send_sensitive_externally=False,
        can_log_notes=False,
        can_view_audit_log=False,
        max_records_per_query=0,
        requires_patient_relationship=False,
        requires_purpose_of_use=True,
    ),
    "it_admin": RolePolicy(
        role="it_admin",
        can_query_records=False,
        can_view_sensitive=False,
        can_view_restricted=False,
        can_send_to_vendors=False,
        can_send_sensitive_externally=False,
        can_log_notes=False,
        can_view_audit_log=True,
        max_records_per_query=0,
        requires_patient_relationship=False,
        requires_purpose_of_use=False,
    ),
    "external_auditor": RolePolicy(
        role="external_auditor",
        can_query_records=False,
        can_view_sensitive=False,
        can_view_restricted=False,
        can_send_to_vendors=False,
        can_send_sensitive_externally=False,
        can_log_notes=False,
        can_view_audit_log=True,
        max_records_per_query=0,
        requires_patient_relationship=False,
        requires_purpose_of_use=False,
    ),
}


def get_policy(role: ClinicalRole) -> RolePolicy:
    return ROLE_POLICIES[role]


def can_access_record(role: ClinicalRole, sensitivity: str) -> tuple[bool, str]:
    """Returns (allowed, denial_reason)."""
    policy = get_policy(role)
    if sensitivity == "RESTRICTED" and not policy.can_view_restricted:
        return False, (
            f"Role '{role}' is not authorized to access RESTRICTED records "
            "(psychiatric, genetic). Requires separate patient authorization "
            "under 42 CFR Part 2 / state mental health law."
        )
    if sensitivity == "SENSITIVE" and not policy.can_view_sensitive:
        return False, (
            f"Role '{role}' is not authorized to access SENSITIVE records "
            "(substance use, HIV, reproductive). Minimum necessary access denied."
        )
    if not policy.can_query_records:
        return False, (
            f"Role '{role}' does not have read access to patient records. "
            "Use generate_deidentified_summary() for research access."
        )
    return True, ""
