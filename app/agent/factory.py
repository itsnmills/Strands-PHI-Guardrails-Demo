"""
app/agent/factory.py
─────────────────────
Agent factory: constructs a role-scoped HIPAA agent for each request.

Each agent instance is scoped to:
  - A specific clinical role (affects which tools are usable)
  - A declared purpose of use (affects what data scope is allowed)
  - A shared audit logger (records all decisions)

The system prompt is role-aware: different roles receive different
instructions about what they can and cannot do.
"""

import os
from strands import Agent
from strands.models.litellm import LiteLLMModel

from app.guardrails.steering_handler import HIPAASteeringHandler
from app.guardrails.audit_logger import AuditLogger
from app.tools.clinical_tools import (
    query_patient_record,
    get_deidentified_summary,
    send_data_to_vendor,
    check_vendor_baa_status,
    log_clinical_note,
    set_audit_logger,
)
from app.policies.rbac import ClinicalRole, ROLE_DESCRIPTIONS


ROLE_SYSTEM_PROMPTS: dict[str, str] = {
    "physician": """You are a HIPAA-compliant clinical AI assistant for a treating physician.
You have access to patient records for patients under your care.
You MUST: declare a purpose of use, use minimum necessary data, and de-identify before external transmission.
You MUST NOT: send raw PHI to external vendors, share records with unapproved systems.""",

    "nurse": """You are a HIPAA-compliant clinical AI assistant for a registered nurse.
You can access clinical summaries for patients on your assigned floor.
You MUST NOT: access psychiatric (RESTRICTED) records without separate authorization.
You MUST NOT: transmit data to external vendors — route those requests to a physician.""",

    "billing_staff": """You are a HIPAA-compliant AI assistant for billing and revenue cycle staff.
You have access to billing-relevant data only (diagnosis codes, procedure codes, dates of service).
You MUST NOT: access clinical notes, full diagnoses, or medication details — only billing codes.
You MUST NOT: log clinical notes or access SENSITIVE/RESTRICTED records.""",

    "researcher": """You are a HIPAA-compliant AI assistant for an IRB-approved researcher.
You CANNOT access raw patient records — only de-identified summaries via get_deidentified_summary().
You MUST use purpose='research' for all summaries.
All data you receive is de-identified and must not be re-identified.""",

    "it_admin": """You are a system administration AI assistant.
You have NO access to patient records or clinical data.
You can view audit logs and system configuration information only.""",

    "external_auditor": """You are an external compliance auditor AI assistant.
You have read-only access to audit logs for compliance review.
You have NO access to patient PHI, clinical data, or operational controls.""",
}


def create_agent(
    role: ClinicalRole,
    actor_id: str,
    purpose: str,
    justification: str,
    audit_logger: AuditLogger,
) -> tuple[Agent, HIPAASteeringHandler]:
    """
    Create a role-scoped HIPAA agent.
    
    Returns (agent, steering_handler) so the UI can read guardrail events.
    """
    # Register audit logger with tools
    set_audit_logger(audit_logger)

    model = LiteLLMModel(
        model_id="openai/gpt-4o",
        params={
            "api_key": os.environ.get("OPENROUTER_API_KEY", ""),
            "base_url": "https://openrouter.ai/api/v1",
        },
    )

    steering = HIPAASteeringHandler(
        role=role,
        actor_id=actor_id,
        purpose=purpose,
        justification=justification,
        audit_logger=audit_logger,
    )

    system_prompt = ROLE_SYSTEM_PROMPTS.get(role, ROLE_SYSTEM_PROMPTS["physician"])
    role_context = f"\n\nCurrent session:\n- Role: {role}\n- Purpose: {purpose}\n- Actor: {actor_id}"

    agent = Agent(
        model=model,
        tools=[
            query_patient_record,
            get_deidentified_summary,
            send_data_to_vendor,
            check_vendor_baa_status,
            log_clinical_note,
        ],
        plugins=[steering],
        system_prompt=system_prompt + role_context,
    )

    return agent, steering
