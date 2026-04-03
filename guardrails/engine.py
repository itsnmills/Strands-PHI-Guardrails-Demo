"""
guardrails/engine.py
────────────────────
Standalone HIPAA guardrail engine.

No Strands dependency. No external packages. Pure Python 3.10+.
Runs in ~1ms on any server.

Call check() before any external action that touches PHI:
  - LLM calls with patient context
  - Email/Slack/webhook sends
  - Vendor API calls
  - Database writes

The engine is stateless and thread-safe. Instantiate once, call many times.
"""

from __future__ import annotations

import re
import json
import datetime
from dataclasses import dataclass, field, asdict
from typing import Literal, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Types
# ─────────────────────────────────────────────────────────────────────────────

ClinicalRole = Literal[
    "physician",
    "nurse",
    "billing_staff",
    "researcher",
    "it_admin",
    "external_auditor",
]

PurposeCode = Literal[
    "TREATMENT",
    "PAYMENT",
    "OPERATIONS",
    "RESEARCH",
    "LEGAL",
    "PUBLIC_HEALTH",
    "HANDOFF",
    "AUDIT",
]

Sensitivity = Literal["STANDARD", "SENSITIVE", "RESTRICTED"]


# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    """
    Returned by check(). The only field you need in the hot path is `blocked`.

    if result.blocked:
        raise GuardrailBlocked(result.reason)
    """
    blocked: bool
    rule: str                    # which control triggered (e.g. "Sensitivity Tier: Access Denied")
    reason: str                  # human-readable denial reason (or "" if allowed)
    role: str
    purpose: str
    tool: str
    risk_score: float            # 0.0–1.0 PHI confidence score
    phi_types: list[str]         # e.g. ["ssn", "dob_labeled"]
    redacted_payload: str        # payload with PHI replaced by [TYPE] tokens
    timestamp: str               # ISO 8601
    layer: int                   # which of the 6 control layers triggered (0 = allowed)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def __bool__(self) -> bool:
        """Truthy = allowed. So `if result:` means proceed."""
        return not self.blocked


class GuardrailBlocked(Exception):
    """Raise this when check() returns blocked=True and you want to abort."""
    def __init__(self, result: CheckResult):
        self.result = result
        super().__init__(f"[{result.rule}] {result.reason}")


# ─────────────────────────────────────────────────────────────────────────────
# RBAC policy matrix
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _RolePolicy:
    can_query_records: bool
    can_view_sensitive: bool
    can_view_restricted: bool
    can_send_to_vendors: bool
    can_log_notes: bool
    can_view_audit_log: bool
    clinical_tool_access: bool    # query_patient_record, send_data_to_vendor, log_clinical_note
    max_records_per_query: int


_ROLE_POLICIES: dict[str, _RolePolicy] = {
    "physician": _RolePolicy(
        can_query_records=True,
        can_view_sensitive=True,
        can_view_restricted=True,
        can_send_to_vendors=True,
        can_log_notes=True,
        can_view_audit_log=False,
        clinical_tool_access=True,
        max_records_per_query=5,
    ),
    "nurse": _RolePolicy(
        can_query_records=True,
        can_view_sensitive=True,
        can_view_restricted=False,
        can_send_to_vendors=False,
        can_log_notes=True,
        can_view_audit_log=False,
        clinical_tool_access=True,
        max_records_per_query=3,
    ),
    "billing_staff": _RolePolicy(
        can_query_records=True,
        can_view_sensitive=False,
        can_view_restricted=False,
        can_send_to_vendors=True,
        can_log_notes=False,
        can_view_audit_log=False,
        clinical_tool_access=True,
        max_records_per_query=10,
    ),
    "researcher": _RolePolicy(
        can_query_records=False,
        can_view_sensitive=False,
        can_view_restricted=False,
        can_send_to_vendors=False,
        can_log_notes=False,
        can_view_audit_log=False,
        clinical_tool_access=False,
        max_records_per_query=0,
    ),
    "it_admin": _RolePolicy(
        can_query_records=False,
        can_view_sensitive=False,
        can_view_restricted=False,
        can_send_to_vendors=False,
        can_log_notes=False,
        can_view_audit_log=True,
        clinical_tool_access=False,
        max_records_per_query=0,
    ),
    "external_auditor": _RolePolicy(
        can_query_records=False,
        can_view_sensitive=False,
        can_view_restricted=False,
        can_send_to_vendors=False,
        can_log_notes=False,
        can_view_audit_log=True,
        clinical_tool_access=False,
        max_records_per_query=0,
    ),
}

_CLINICAL_TOOLS = {
    "query_patient_record",
    "send_data_to_vendor",
    "log_clinical_note",
    "get_deidentified_summary",
}


# ─────────────────────────────────────────────────────────────────────────────
# Purpose-of-use policy
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _PurposePolicy:
    phi_access_allowed: bool
    requires_justification: bool
    allowed_roles: list[str]


_PURPOSE_POLICIES: dict[str, _PurposePolicy] = {
    "TREATMENT":     _PurposePolicy(True,  False, ["physician", "nurse"]),
    "PAYMENT":       _PurposePolicy(True,  True,  ["billing_staff", "physician"]),
    "OPERATIONS":    _PurposePolicy(True,  True,  ["physician", "nurse", "it_admin"]),
    "RESEARCH":      _PurposePolicy(False, True,  ["researcher"]),
    "LEGAL":         _PurposePolicy(True,  True,  ["physician", "it_admin"]),
    "PUBLIC_HEALTH": _PurposePolicy(True,  True,  ["physician", "nurse"]),
    "HANDOFF":       _PurposePolicy(True,  False, ["physician", "nurse"]),
    "AUDIT":         _PurposePolicy(False, True,  ["it_admin", "external_auditor"]),
}


# ─────────────────────────────────────────────────────────────────────────────
# BAA vendor registry
# ─────────────────────────────────────────────────────────────────────────────

# vendor_id → sensitivity tiers that vendor's BAA covers
_VENDOR_REGISTRY: dict[str, list[str]] = {
    "epic-systems":       ["STANDARD", "SENSITIVE", "RESTRICTED"],
    "cerner":             ["STANDARD", "SENSITIVE", "RESTRICTED"],
    "azure-openai":       ["STANDARD"],
    "aws-bedrock":        ["STANDARD"],
    "change-healthcare":  ["STANDARD"],
    "internal":           ["STANDARD", "SENSITIVE", "RESTRICTED"],
}

# Consumer platforms — blocked regardless of intent
_BLOCKED_PLATFORMS: set[str] = {
    "slack", "discord", "teams", "gmail",
    "whatsapp", "chatgpt", "dropbox", "notion",
}


# ─────────────────────────────────────────────────────────────────────────────
# PHI detector (confidence-weighted)
# ─────────────────────────────────────────────────────────────────────────────

_PHI_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    ("ssn",            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.97),
    ("mrn",            re.compile(r"\bMRN[:\s]*\d{5,}\b", re.IGNORECASE), 0.95),
    ("dob_labeled",    re.compile(r"\b(DOB|Date of Birth|born)[:\s]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", re.IGNORECASE), 0.95),
    ("email",          re.compile(r"\b[\w.\-+]+@[\w.\-]+\.[a-z]{2,}\b", re.IGNORECASE), 0.90),
    ("phone_us",       re.compile(r"\b(\+1[\s.-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b"), 0.87),
    ("health_plan",    re.compile(r"\b(health plan|member id|subscriber id|group number)[:\s]*[\w\-]{5,}\b", re.IGNORECASE), 0.85),
    ("mrn_generic",    re.compile(r"\b(medical record|patient id|pat id)[:\s]*[A-Z0-9]{4,}\b", re.IGNORECASE), 0.85),
    ("account_num",    re.compile(r"\b(account|acct|account number)[:\s]*\d{6,}\b", re.IGNORECASE), 0.82),
    ("address_street", re.compile(r"\b\d+\s+[A-Z][a-z]+\s+(Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Blvd|Boulevard)\b", re.IGNORECASE), 0.80),
    ("name_full",      re.compile(r"\b[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}\b"), 0.55),
    ("ip_address",     re.compile(r"\bIP[:\s]*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", re.IGNORECASE), 0.90),
    ("license_num",    re.compile(r"\b(driver[s']? license|drv license)[:\s]*[A-Z0-9]{5,}\b", re.IGNORECASE), 0.85),
    ("biometric",      re.compile(r"\b(fingerprint|retina scan|iris scan|voice print)[:\s]*\w+\b", re.IGNORECASE), 0.88),
    ("zip_code",       re.compile(r"\b\d{5}(-\d{4})?\b"), 0.35),
]

_HIGH_CONF_THRESHOLD = 0.70
_BLOCK_RISK_THRESHOLD = 0.60


@dataclass
class _PhiResult:
    phi_found: bool
    risk_score: float
    high_confidence_types: list[str]
    all_types: list[str]
    redacted_text: str
    should_block: bool


def _detect_phi(text: str) -> _PhiResult:
    if not text:
        return _PhiResult(False, 0.0, [], [], text or "", False)

    matches: list[tuple[str, float, int, int, str]] = []  # (type, conf, start, end, matched)
    seen_spans: set[tuple[int, int]] = set()

    for phi_type, pattern, confidence in _PHI_PATTERNS:
        for m in pattern.finditer(text):
            span = (m.start(), m.end())
            if any(abs(s - span[0]) < 10 for s, _ in seen_spans):
                continue
            seen_spans.add(span)
            matches.append((phi_type, confidence, m.start(), m.end(), m.group()))

    if not matches:
        return _PhiResult(False, 0.0, [], [], text, False)

    risk_score = max(conf for _, conf, *_ in matches)
    high_conf = [t for t, c, *_ in matches if c >= _HIGH_CONF_THRESHOLD]
    all_types  = [t for t, *_ in matches]

    # Redact from end to start to preserve offsets
    redacted = text
    for phi_type, _, start, end, _ in sorted(matches, key=lambda x: x[2], reverse=True):
        label = f"[{phi_type.upper().replace('_', '-')}]"
        redacted = redacted[:start] + label + redacted[end:]

    return _PhiResult(
        phi_found=True,
        risk_score=risk_score,
        high_confidence_types=high_conf,
        all_types=all_types,
        redacted_text=redacted,
        should_block=risk_score >= _BLOCK_RISK_THRESHOLD,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Patient sensitivity registry (extend with your own data source)
# ─────────────────────────────────────────────────────────────────────────────

# patient_id → sensitivity tier
# In production: replace with a DB lookup or cache
_PATIENT_SENSITIVITY: dict[str, Sensitivity] = {
    "P001": "STANDARD",     # Jane Doe — Endocrinology
    "P002": "SENSITIVE",    # John Smith — Opioid Use Disorder
    "P003": "RESTRICTED",   # Sarah Connor — Behavioral Health
    "P004": "STANDARD",     # Robert Chen — Oncology
}


# ─────────────────────────────────────────────────────────────────────────────
# Core check() function
# ─────────────────────────────────────────────────────────────────────────────

def check(
    role: str,
    purpose: str,
    tool: str,
    *,
    patient_id: str = "",
    vendor_id: str = "",
    payload: str = "",
    justification: str = "",
    patient_sensitivity: Optional[str] = None,  # override registry lookup
) -> CheckResult:
    """
    Run all 6 HIPAA control layers and return a CheckResult.

    Parameters
    ----------
    role            : ClinicalRole — the authenticated user's role
    purpose         : PurposeCode  — declared purpose of use
    tool            : str          — the action being requested
                                     (e.g. "query_patient_record",
                                      "send_data_to_vendor",
                                      "send_email", "call_llm")
    patient_id      : str          — patient identifier for sensitivity lookup
    vendor_id       : str          — destination system identifier
    payload         : str          — the text/data being processed or sent
    justification   : str          — free-text reason (required for some purposes)
    patient_sensitivity : str      — override registry lookup (STANDARD/SENSITIVE/RESTRICTED)

    Returns
    -------
    CheckResult
        .blocked  → True = stop, do not proceed
        .reason   → why it was blocked (empty string if allowed)
        .rule     → which control layer triggered

    Raises
    ------
    ValueError if role or purpose is not recognized.
    """

    ts = datetime.datetime.utcnow().isoformat() + "Z"

    # Validate role
    if role not in _ROLE_POLICIES:
        raise ValueError(
            f"Unknown role '{role}'. Valid roles: {list(_ROLE_POLICIES)}"
        )

    # Validate purpose
    if purpose not in _PURPOSE_POLICIES:
        raise ValueError(
            f"Unknown purpose '{purpose}'. Valid codes: {list(_PURPOSE_POLICIES)}"
        )

    policy = _ROLE_POLICIES[role]
    pou    = _PURPOSE_POLICIES[purpose]

    def _blocked(rule: str, reason: str, layer: int, phi: _PhiResult | None = None) -> CheckResult:
        p = phi or _PhiResult(False, 0.0, [], [], payload, False)
        return CheckResult(
            blocked=True,
            rule=rule,
            reason=reason,
            role=role,
            purpose=purpose,
            tool=tool,
            risk_score=p.risk_score,
            phi_types=p.all_types,
            redacted_payload=p.redacted_text,
            timestamp=ts,
            layer=layer,
        )

    def _allowed(phi: _PhiResult | None = None) -> CheckResult:
        p = phi or _PhiResult(False, 0.0, [], [], payload, False)
        return CheckResult(
            blocked=False,
            rule="",
            reason="",
            role=role,
            purpose=purpose,
            tool=tool,
            risk_score=p.risk_score,
            phi_types=p.all_types,
            redacted_payload=p.redacted_text,
            timestamp=ts,
            layer=0,
        )

    # ── Layer 1: RBAC ────────────────────────────────────────────────────────

    # Researcher cannot query raw records
    if tool == "query_patient_record" and not policy.can_query_records:
        return _blocked(
            "RBAC: Record Access Denied",
            f"Role '{role}' cannot query raw patient records. "
            "Use get_deidentified_summary() for research access.",
            layer=1,
        )

    # IT / auditor cannot use clinical tools
    if role in ("it_admin", "external_auditor") and tool in _CLINICAL_TOOLS:
        return _blocked(
            "RBAC: Role Not Authorized",
            f"Role '{role}' does not have access to clinical tools. "
            "Restricted to system and audit functions only.",
            layer=1,
        )

    # Billing cannot log clinical notes
    if role == "billing_staff" and tool == "log_clinical_note":
        return _blocked(
            "RBAC: Billing Cannot Log Clinical Notes",
            "Billing staff are not authorized to create clinical documentation. "
            "This violates role segregation requirements.",
            layer=1,
        )

    # ── Layer 2: Purpose-of-use ──────────────────────────────────────────────

    if role not in pou.allowed_roles:
        return _blocked(
            "Purpose-of-Use Violation",
            f"Role '{role}' is not authorized to use purpose '{purpose}'. "
            f"Authorized roles: {pou.allowed_roles}.",
            layer=2,
        )

    if pou.requires_justification and not justification.strip():
        return _blocked(
            "Purpose-of-Use: Justification Required",
            f"Purpose '{purpose}' requires a written justification before PHI access. "
            "Provide a brief explanation of why this access is needed.",
            layer=2,
        )

    # ── Layer 3: BAA vendor registry ─────────────────────────────────────────

    if tool == "send_data_to_vendor" or (vendor_id and tool not in _CLINICAL_TOOLS):
        if vendor_id in _BLOCKED_PLATFORMS:
            return _blocked(
                "BAA: Blocked Consumer Platform",
                f"'{vendor_id}' is not BAA-eligible (consumer platform). "
                "PHI may not be transmitted to consumer messaging or storage services. "
                "Use a BAA-covered alternative.",
                layer=3,
            )

        if vendor_id and vendor_id not in _VENDOR_REGISTRY:
            return _blocked(
                "BAA: Unregistered Vendor",
                f"Vendor '{vendor_id}' is not in the BAA registry. "
                "PHI cannot be transmitted to an unvetted external system. "
                f"Approved vendors: {list(_VENDOR_REGISTRY)}",
                layer=3,
            )

    # ── Layer 4: PHI content scan ─────────────────────────────────────────────

    phi_result = _detect_phi(payload) if payload else None

    if phi_result and phi_result.should_block and tool in (
        "send_data_to_vendor", "send_email", "post_message",
        "call_llm", "webhook", "send_to_vendor",
    ):
        return _blocked(
            "PHI Output Filter: Raw PHI Detected",
            f"Payload contains raw PHI: {phi_result.high_confidence_types} "
            f"(risk score: {phi_result.risk_score:.2f}). "
            "De-identify before transmitting externally. "
            "Use the .redacted_payload field for a safe version.",
            layer=4,
            phi=phi_result,
        )

    # ── Layer 5: Sensitivity tier ─────────────────────────────────────────────

    if tool == "query_patient_record" and patient_id:
        sensitivity = patient_sensitivity or _PATIENT_SENSITIVITY.get(patient_id, "STANDARD")

        if sensitivity == "RESTRICTED" and not policy.can_view_restricted:
            return _blocked(
                "Sensitivity Tier: Access Denied",
                f"Role '{role}' is not authorized to access RESTRICTED records "
                "(psychiatric, genetic). Requires separate patient authorization "
                "under 42 CFR Part 2 / state mental health law.",
                layer=5,
                phi=phi_result,
            )

        if sensitivity == "SENSITIVE" and not policy.can_view_sensitive:
            return _blocked(
                "Sensitivity Tier: Access Denied",
                f"Role '{role}' is not authorized to access SENSITIVE records "
                "(substance use, HIV, reproductive). Minimum necessary access denied.",
                layer=5,
                phi=phi_result,
            )

    # ── Layer 5b: BAA sensitivity mismatch ───────────────────────────────────

    if vendor_id and vendor_id in _VENDOR_REGISTRY and patient_id:
        sensitivity = patient_sensitivity or _PATIENT_SENSITIVITY.get(patient_id, "STANDARD")
        allowed_tiers = _VENDOR_REGISTRY[vendor_id]
        if sensitivity not in allowed_tiers:
            return _blocked(
                "BAA: Sensitivity Tier Mismatch",
                f"Vendor '{vendor_id}' BAA does not cover {sensitivity} data. "
                f"This vendor is approved for: {allowed_tiers}. "
                "De-identify the data or use an appropriate vendor.",
                layer=5,
                phi=phi_result,
            )

    # ── Layer 6: Minimum necessary ────────────────────────────────────────────
    # (Enforced at the tool layer in production — placeholder for extensibility)

    return _allowed(phi_result)
