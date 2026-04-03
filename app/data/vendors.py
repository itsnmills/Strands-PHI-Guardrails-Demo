"""
app/data/vendors.py
───────────────────
BAA-approved vendor registry with capability tiers and allowed data types.
In production this would be a database table backed by a vendor management process.
"""

from dataclasses import dataclass
from typing import Literal

VendorTier = Literal["primary_ehr", "secondary_ehr", "ai_processing", "billing", "internal", "research"]


@dataclass
class Vendor:
    vendor_id: str
    display_name: str
    tier: VendorTier
    baa_signed: bool
    baa_expiry: str
    allowed_sensitivity: list[str]   # which tiers this vendor may receive
    notes: str = ""


VENDOR_REGISTRY: dict[str, Vendor] = {
    "epic-systems": Vendor(
        vendor_id="epic-systems",
        display_name="Epic Systems (EHR)",
        tier="primary_ehr",
        baa_signed=True,
        baa_expiry="2027-12-31",
        allowed_sensitivity=["STANDARD", "SENSITIVE", "RESTRICTED"],
        notes="Full EHR integration. Primary system of record.",
    ),
    "cerner": Vendor(
        vendor_id="cerner",
        display_name="Oracle Health (Cerner)",
        tier="secondary_ehr",
        baa_signed=True,
        baa_expiry="2027-06-30",
        allowed_sensitivity=["STANDARD", "SENSITIVE"],
        notes="Secondary EHR used by affiliated clinics.",
    ),
    "azure-openai": Vendor(
        vendor_id="azure-openai",
        display_name="Microsoft Azure OpenAI",
        tier="ai_processing",
        baa_signed=True,
        baa_expiry="2026-12-31",
        allowed_sensitivity=["STANDARD"],
        notes="AI inference only. STANDARD data after de-identification only.",
    ),
    "aws-bedrock": Vendor(
        vendor_id="aws-bedrock",
        display_name="AWS Bedrock",
        tier="ai_processing",
        baa_signed=True,
        baa_expiry="2026-12-31",
        allowed_sensitivity=["STANDARD"],
        notes="AI inference only. De-identified data only.",
    ),
    "change-healthcare": Vendor(
        vendor_id="change-healthcare",
        display_name="Change Healthcare (Billing)",
        tier="billing",
        baa_signed=True,
        baa_expiry="2027-03-31",
        allowed_sensitivity=["STANDARD"],
        notes="Claims processing. Minimum necessary billing data only.",
    ),
    "internal": Vendor(
        vendor_id="internal",
        display_name="Internal Hospital Systems",
        tier="internal",
        baa_signed=True,
        baa_expiry="2099-12-31",
        allowed_sensitivity=["STANDARD", "SENSITIVE", "RESTRICTED"],
        notes="Internal systems. Subject to RBAC controls.",
    ),
    # ── Non-approved (blocked) ──────────────────────────────────
    # These are NOT in the registry — any vendor_id not present is blocked.
    # Included here as comments for documentation purposes:
    # "slack", "discord", "teams", "gmail", "whatsapp", "dropbox"
}

BLOCKED_PLATFORMS = {
    "slack": "Consumer messaging — no BAA available",
    "discord": "Consumer messaging — no BAA available",
    "teams": "Microsoft Teams consumer — use BAA-covered Azure tenant only",
    "gmail": "Consumer email — use HIPAA-compliant email gateway only",
    "whatsapp": "Consumer messaging — not HIPAA eligible",
    "dropbox": "Consumer storage — use BAA-covered cloud storage only",
    "chatgpt": "OpenAI consumer product — use azure-openai with BAA instead",
}
