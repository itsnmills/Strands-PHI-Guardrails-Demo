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
import uuid

import litellm
from strands import Agent
from strands.models.litellm import LiteLLMModel

from app.agent.traffic import TRAFFIC
from app.guardrails.steering_handler import HIPAASteeringHandler


class GoLiteLLMModel(LiteLLMModel):
    """
    LiteLLMModel tuned for the OpenCode Go gateway: strips reasoning fields
    (reasoning_content / reasoning) from formatted messages. Reasoning models
    emit those on assistant turns, and the Go endpoint rejects them on
    multi-turn Chat Completions calls ("reasoningContent is not supported…").
    """

    def format_request(self, messages, tool_specs=None, system_prompt=None, tool_choice=None, *,
                       system_prompt_content=None, **kwargs):
        request = super().format_request(
            messages, tool_specs, system_prompt, tool_choice,
            system_prompt_content=system_prompt_content, **kwargs,
        )
        for msg in request.get("messages", []):
            if isinstance(msg, dict):
                for field in ("reasoning_content", "reasoning", "reasoningContent"):
                    msg.pop(field, None)
        return request
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
    session_monitor=None,
    break_glass=None,
    model: str | None = None,
    traffic_store: list | None = None,
) -> tuple[Agent, HIPAASteeringHandler]:
    """
    Create a role-scoped HIPAA agent.

    Returns (agent, steering_handler) so the UI can read guardrail events.
    `session_monitor` and `break_glass` are optional shared session objects;
    when provided, the steering layer gains behavioral minimum-necessary
    enforcement and the break-glass emergency path. `model` overrides the
    PHI_DEMO_MODEL environment default (both live on OpenCode Go).
    `traffic_store` receives a full record of every LLM request/response.
    """
    # Register audit logger with tools
    set_audit_logger(audit_logger)

    # OpenCode Go requires a stable per-conversation session id and a
    # self-identifying user agent so requests can be routed and cached
    # (https://opencode.ai/docs/go/#where-can-i-use-it)
    go_headers = {
        "x-opencode-session": f"phidemo-{os.getpid()}-{str(uuid.uuid4())[:8]}",
        "User-Agent": "phidemo-console/1.0 (HIPAA-guardrails demo)",
    }

    model = GoLiteLLMModel(
        model_id=f"openai/{model or os.environ.get('PHI_DEMO_MODEL', 'glm-5.3-flash')}",
        params={
            "api_key": os.environ.get("OPENCODE_API_KEY", "")
            or os.environ.get("OPENROUTER_API_KEY", ""),
            "base_url": os.environ.get(
                "PHI_DEMO_BASE_URL", "https://opencode.ai/zen/go/v1"
            ),
            "extra_headers": go_headers,
        },
    )

    # Full request/response visibility: every LLM call lands in the store
    TRAFFIC.bind(traffic_store if traffic_store is not None else [])
    litellm.callbacks = [TRAFFIC]

    steering = HIPAASteeringHandler(
        role=role,
        actor_id=actor_id,
        purpose=purpose,
        justification=justification,
        audit_logger=audit_logger,
        session_monitor=session_monitor,
        break_glass=break_glass,
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
