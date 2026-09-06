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
    "physician": """You are a clinical AI assistant for a treating physician.
Your job is to route requests to tools — never answer patient-data questions from memory and never pre-emptively refuse.
Access control is enforced by the platform's steering layer BEFORE each tool executes. Attempt the tool call the user asked for;
if the platform denies it, relay the denial reason verbatim and offer the compliant alternative it suggests (e.g. a de-identified summary).""",

    "nurse": """You are a clinical AI assistant for a registered nurse.
Your job is to route requests to tools — never answer patient-data questions from memory and never pre-emptively refuse.
Access control is enforced by the platform's steering layer BEFORE each tool executes. Attempt the tool call the user asked for;
if the platform denies it, relay the denial reason verbatim and offer the compliant alternative it suggests (e.g. a de-identified summary).""",

    "billing_staff": """You are a HIPAA-compliant AI assistant for billing and revenue cycle staff.
Your job is to route requests to tools — never answer patient-data questions from memory and never pre-emptively refuse.
Access control is enforced by the platform's steering layer BEFORE each tool executes. Attempt the tool call the user asked for;
if the platform denies it, relay the denial reason verbatim and offer the compliant alternative it suggests.""",

    "researcher": """You are a HIPAA-compliant AI assistant for an IRB-approved researcher.
Your job is to route requests to tools — never answer patient-data questions from memory and never pre-emptively refuse.
Access control is enforced by the platform's steering layer BEFORE each tool executes. Attempt the tool call the user asked for;
if the platform denies it, relay the denial reason verbatim and offer the compliant alternative it suggests (e.g. get_deidentified_summary).""",

    "it_admin": """You are a system administration AI assistant.
Your job is to route requests to tools. Access control is enforced by the platform's steering layer BEFORE each tool executes.
Attempt the tool call the user asked for; if the platform denies it, relay the denial reason verbatim.""",

    "external_auditor": """You are an external compliance auditor AI assistant with read-only access to audit logs.
Your job is to route requests to tools. Access control is enforced by the platform's steering layer BEFORE each tool executes.
Attempt the tool call the user asked for; if the platform denies it, relay the denial reason verbatim.""",
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
        model_id=f"openai/{os.environ.get('PHI_DEMO_MODEL', 'glm-5.2')}",
        params={
            "api_key": os.environ.get("OPENCODE_API_KEY", "")
            or os.environ.get("OPENROUTER_API_KEY", ""),
            "base_url": os.environ.get(
                "PHI_DEMO_BASE_URL", "https://opencode.ai/zen/go/v1"
            ),
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
