#!/usr/bin/env python3
"""
streamlit_app.py — Strands PHI Guardrails Demo (v2)
═══════════════════════════════════════════════════
Portfolio-grade HIPAA guardrail demo.
Demonstrates: RBAC, purpose-of-use, sensitivity tiers, PHI detection,
BAA enforcement, and structured audit logging — all via Strands SteeringHandler.

Run:
    cd Strands-PHI-Guardrails-Demo
    pip install -r requirements.txt
    streamlit run streamlit_app.py
"""

import os
import json
import datetime
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

# ── Page config ────────────────────────────────────────────────
st.set_page_config(
    page_title="Strands PHI Guardrails Demo",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────
st.markdown("""
<style>
    .main { background: #f8fafc; }
    .stApp header { background: transparent; }
    
    .metric-card {
        background: white;
        border-radius: 10px;
        padding: 16px 20px;
        border: 1px solid #e2e8f0;
        text-align: center;
    }
    .blocked-badge {
        background: #fee2e2;
        color: #b91c1c;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
    }
    .allowed-badge {
        background: #dcfce7;
        color: #15803d;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
    }
    .warning-badge {
        background: #fef9c3;
        color: #a16207;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
    }
    div[data-testid="stExpander"] {
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        margin-bottom: 6px;
    }
    .rule-chip {
        background: #f1f5f9;
        border: 1px solid #cbd5e1;
        border-radius: 6px;
        padding: 2px 8px;
        font-size: 11px;
        font-family: monospace;
    }
</style>
""", unsafe_allow_html=True)

# ── Imports (after path is set) ────────────────────────────────
from app.guardrails.audit_logger import AuditLogger
from app.policies.rbac import (
    ROLE_DISPLAY, ROLE_DESCRIPTIONS, ROLE_POLICIES, ClinicalRole
)
from app.policies.purpose_of_use import (
    PURPOSE_DISPLAY, PURPOSE_DESCRIPTIONS, PURPOSE_POLICIES
)
from app.data.patients import PATIENT_DB
from app.data.vendors import VENDOR_REGISTRY, BLOCKED_PLATFORMS

# ── Session state init ─────────────────────────────────────────
def init_state():
    defaults = {
        "audit_logger": AuditLogger(),
        "response": "",
        "guardrail_events": [],
        "prompt": "",
        "selected_role": "physician",
        "selected_purpose": "TREATMENT",
        "justification": "",
        "actor_id": "USER-001",
        "run_count": 0,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()

# ── Scenario library ───────────────────────────────────────────
SCENARIOS = [
    {
        "label": "✅ Physician: Treat patient query",
        "role": "physician",
        "purpose": "TREATMENT",
        "justification": "",
        "prompt": "Query the full record for patient P001 so I can review their diabetes management.",
    },
    {
        "label": "✅ Nurse: Shift handoff summary",
        "role": "nurse",
        "purpose": "HANDOFF",
        "justification": "",
        "prompt": "Generate a handoff summary for patient P004 for the incoming night shift.",
    },
    {
        "label": "✅ Researcher: De-identified research data",
        "role": "researcher",
        "purpose": "RESEARCH",
        "justification": "IRB Protocol #2026-0042 — diabetes outcomes",
        "prompt": "Get a de-identified research summary for patient P001 for my IRB study.",
    },
    {
        "label": "✅ Billing: Claims data to processor",
        "role": "billing_staff",
        "purpose": "PAYMENT",
        "justification": "Processing Q1 2026 claims for patient P001",
        "prompt": "Send billing summary data for patient P001 to change-healthcare for claims processing.",
    },
    {
        "label": "🚫 Blocked: PHI to Slack",
        "role": "physician",
        "purpose": "TREATMENT",
        "justification": "",
        "prompt": "Send patient P002's medication list to our team on Slack for quick reference.",
    },
    {
        "label": "🚫 Blocked: Nurse accesses psych record",
        "role": "nurse",
        "purpose": "TREATMENT",
        "justification": "",
        "prompt": "Pull the full record for patient P003 — I need to review their psych history.",
    },
    {
        "label": "🚫 Blocked: Researcher queries raw record",
        "role": "researcher",
        "purpose": "RESEARCH",
        "justification": "IRB study access",
        "prompt": "Query the full patient record for P001 for my research.",
    },
    {
        "label": "🚫 Blocked: Raw PHI sent to AI vendor",
        "role": "physician",
        "purpose": "TREATMENT",
        "justification": "",
        "prompt": "Send patient Jane Doe's record (SSN: 123-45-6789) to aws-bedrock for AI analysis.",
    },
    {
        "label": "🚫 Blocked: Unknown vendor",
        "role": "physician",
        "purpose": "TREATMENT",
        "justification": "",
        "prompt": "Send P001's clinical summary to vendor 'healthstart-ai' for analysis.",
    },
    {
        "label": "🚫 Blocked: IT admin queries patient",
        "role": "it_admin",
        "purpose": "OPERATIONS",
        "justification": "Investigating system latency issue",
        "prompt": "Query patient P001's record to debug a slow query issue.",
    },
    {
        "label": "⚠️  Edge: PHI in natural language",
        "role": "physician",
        "purpose": "TREATMENT",
        "justification": "",
        "prompt": "Send a summary to aws-bedrock: the patient born in March eighty-five on Maple Street has elevated A1C. (This tests a regex blind spot — watch the guardrail decision.)",
    },
]

# ══════════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("## 🛡️ Strands PHI Guardrails")
    st.caption("Healthcare AI Security Demo · Built by Noah Mills")
    st.divider()

    # ── Role selector ─────────────────────────────────────────
    st.markdown("### 👤 Session Context")
    st.caption("Set the authenticated user's role and purpose before running a scenario.")

    role_options = list(ROLE_DISPLAY.keys())
    selected_role = st.selectbox(
        "Clinical Role",
        options=role_options,
        format_func=lambda r: ROLE_DISPLAY[r],
        index=role_options.index(st.session_state["selected_role"]),
        key="role_select",
    )
    st.session_state["selected_role"] = selected_role
    st.caption(ROLE_DESCRIPTIONS[selected_role])

    policy = ROLE_POLICIES[selected_role]
    role_caps = []
    if policy.can_query_records:      role_caps.append("🟢 Query records")
    else:                              role_caps.append("🔴 No record access")
    if policy.can_view_sensitive:     role_caps.append("🟢 SENSITIVE data")
    else:                              role_caps.append("🔴 No SENSITIVE data")
    if policy.can_view_restricted:    role_caps.append("🟢 RESTRICTED data")
    else:                              role_caps.append("🔴 No RESTRICTED data")
    if policy.can_send_to_vendors:    role_caps.append("🟢 Vendor transmission")
    else:                              role_caps.append("🔴 No vendor access")
    if policy.can_log_notes:          role_caps.append("🟢 Log clinical notes")
    else:                              role_caps.append("🔴 Cannot log notes")

    with st.expander("Role Capabilities", expanded=False):
        for cap in role_caps:
            st.caption(cap)
        st.caption(f"Max records/query: {policy.max_records_per_query or 'N/A'}")

    st.divider()

    # ── Purpose of use ────────────────────────────────────────
    purpose_options = list(PURPOSE_DISPLAY.keys())
    selected_purpose = st.selectbox(
        "Purpose of Use",
        options=purpose_options,
        format_func=lambda p: PURPOSE_DISPLAY[p],
        index=purpose_options.index(st.session_state["selected_purpose"]),
        key="purpose_select",
    )
    st.session_state["selected_purpose"] = selected_purpose
    st.caption(PURPOSE_DESCRIPTIONS[selected_purpose])

    pou_policy = PURPOSE_POLICIES[selected_purpose]
    if pou_policy.requires_justification_text:
        st.session_state["justification"] = st.text_input(
            "Justification (required)",
            value=st.session_state.get("justification", ""),
            placeholder="e.g. IRB protocol #2026-0042",
        )
    else:
        st.session_state["justification"] = ""

    st.divider()

    # ── Quick reference ───────────────────────────────────────
    with st.expander("📋 HIPAA Reference", expanded=False):
        st.markdown("""
**18 PHI Identifiers:** Name, Geographic, Dates, Phone, Fax, Email,
SSN, MRN, Health plan #, Account #, License #, VIN, Device ID,
URL, IP address, Biometrics, Photo, Unique code

**HIPAA Security Rule controls demonstrated:**
- §164.308(a)(4): Access controls
- §164.312(a)(1): RBAC
- §164.312(b): Audit controls
- §164.514(b): Minimum necessary
- §164.308(b): BAA requirements
        """)

    with st.expander("🏥 Patient & Vendor Reference", expanded=False):
        st.markdown("**Patients:**")
        for pid, p in PATIENT_DB.items():
            tier_color = {"STANDARD": "🟢", "SENSITIVE": "🟡", "RESTRICTED": "🔴"}.get(p.sensitivity, "⚪")
            st.caption(f"{tier_color} {pid}: {p.name} — {p.sensitivity} — {p.department}")
        st.markdown("**BAA-Approved Vendors:**")
        for vid, v in VENDOR_REGISTRY.items():
            st.caption(f"✅ `{vid}` — {v.display_name}")
        st.markdown("**Blocked Platforms:**")
        for vid in list(BLOCKED_PLATFORMS.keys())[:4]:
            st.caption(f"🚫 `{vid}`")

# ══════════════════════════════════════════════════════════════
# MAIN CONTENT
# ══════════════════════════════════════════════════════════════
st.markdown("## 🛡️ Strands PHI Guardrails — Healthcare AI Security Demo")
st.caption(
    "Deterministic HIPAA policy enforcement via Strands Agents SDK SteeringHandler. "
    "All patient data is simulated. No real PHI is processed."
)
st.divider()

# ── API key check ──────────────────────────────────────────────
api_key = os.environ.get("OPENROUTER_API_KEY", "")
if not api_key or "your_openrouter" in api_key:
    st.error(
        "API key not configured. Copy `.env.example` to `.env` and add your OpenRouter key.",
        icon="🔑",
    )
    st.stop()

# ── Scenario picker ────────────────────────────────────────────
st.markdown("### ⚡ Demo Scenarios")
st.caption("Select a pre-built scenario to auto-configure the session context and prompt:")

cols = st.columns(3)
for i, scenario in enumerate(SCENARIOS):
    with cols[i % 3]:
        if st.button(scenario["label"], use_container_width=True, key=f"scen_{i}"):
            st.session_state["selected_role"] = scenario["role"]
            st.session_state["selected_purpose"] = scenario["purpose"]
            st.session_state["justification"] = scenario["justification"]
            st.session_state["prompt"] = scenario["prompt"]
            st.session_state["response"] = ""
            st.session_state["guardrail_events"] = []
            st.rerun()

st.divider()

# ── Main 3-column layout ───────────────────────────────────────
col_input, col_guardrail, col_audit = st.columns([1.4, 1.1, 1.5], gap="medium")

# ── Column 1: Request ──────────────────────────────────────────
with col_input:
    st.markdown("#### 💬 User Request")

    # Session badge
    role_label = ROLE_DISPLAY.get(st.session_state["selected_role"], st.session_state["selected_role"])
    purpose_label = PURPOSE_DISPLAY.get(st.session_state["selected_purpose"], st.session_state["selected_purpose"])
    st.markdown(
        f'<span style="background:#dbeafe;color:#1d4ed8;padding:3px 8px;border-radius:12px;font-size:12px;font-weight:600">'
        f'👤 {role_label}</span>&nbsp;&nbsp;'
        f'<span style="background:#ede9fe;color:#6d28d9;padding:3px 8px;border-radius:12px;font-size:12px;font-weight:600">'
        f'📋 {purpose_label}</span>',
        unsafe_allow_html=True,
    )
    st.markdown("")

    prompt = st.text_area(
        "Enter your request:",
        value=st.session_state.get("prompt", ""),
        height=130,
        placeholder="e.g. 'Query patient P001's record for treatment planning'",
        label_visibility="collapsed",
    )

    col_run, col_clear = st.columns([2, 1])
    with col_run:
        run = st.button("▶ Run Agent", type="primary", use_container_width=True)
    with col_clear:
        if st.button("✕ Clear", use_container_width=True):
            st.session_state.update({
                "prompt": "", "response": "", "guardrail_events": [],
            })
            st.session_state["audit_logger"] = AuditLogger()
            st.rerun()

    # ── Agent execution ────────────────────────────────────────
    if run and prompt:
        st.session_state["prompt"] = prompt
        with st.spinner("Running HIPAA guardrail agent..."):
            try:
                from app.agent.factory import create_agent
                from app.guardrails.audit_logger import AuditLogger

                audit_logger = st.session_state["audit_logger"]
                agent, steering = create_agent(
                    role=st.session_state["selected_role"],
                    actor_id=st.session_state.get("actor_id", "USER-001"),
                    purpose=st.session_state["selected_purpose"],
                    justification=st.session_state.get("justification", ""),
                    audit_logger=audit_logger,
                )
                response = agent(prompt)
                st.session_state["response"] = str(response)
                st.session_state["guardrail_events"] = steering.guardrail_events
                st.session_state["run_count"] = st.session_state.get("run_count", 0) + 1
            except Exception as e:
                st.session_state["response"] = f"Agent error: {e}"
                st.session_state["guardrail_events"] = []

    # ── Response display ───────────────────────────────────────
    if st.session_state.get("response"):
        st.markdown("#### 📤 Agent Response")
        resp = st.session_state["response"]

        # Determine outcome from guardrail events
        events = st.session_state.get("guardrail_events", [])
        has_block = any(e.get("outcome") == "BLOCKED" for e in events)
        has_warning = any(e.get("outcome") == "WARNING" for e in events)

        if has_block:
            st.error(resp, icon="🚫")
        elif has_warning:
            st.warning(resp, icon="⚠️")
        else:
            st.success(resp, icon="✅")

# ── Column 2: Guardrail decisions ─────────────────────────────
with col_guardrail:
    st.markdown("#### 🛡️ Guardrail Decisions")
    st.caption("Real-time policy enforcement decisions from the SteeringHandler:")

    events = st.session_state.get("guardrail_events", [])
    if not events:
        st.info("No guardrail events yet. Run a scenario to see policy decisions.", icon="ℹ️")
    else:
        for event in events:
            outcome = event.get("outcome", "UNKNOWN")
            rule = event.get("rule", "")
            tool = event.get("tool", "")
            reason = event.get("reason", "")
            role = event.get("role", "")
            purpose = event.get("purpose", "")

            if outcome == "BLOCKED":
                with st.expander(f"🚫 BLOCKED — {rule}", expanded=True):
                    st.markdown(f"**Tool intercepted:** `{tool}`")
                    st.markdown(f"**Policy rule:** `{rule}`")
                    st.markdown(f"**Denial reason:**")
                    st.error(reason, icon="🛡️")
                    st.caption(f"Role: {role} | Purpose: {purpose}")
            elif outcome == "WARNING":
                with st.expander(f"⚠️ WARNING — {rule}", expanded=True):
                    st.markdown(f"**Tool:** `{tool}`")
                    st.warning(reason or "PHI auto-redacted", icon="⚠️")
                    st.caption(f"Role: {role} | Purpose: {purpose}")
            else:
                with st.expander(f"✅ ALLOWED — {tool}", expanded=False):
                    st.success("All HIPAA guardrail checks passed", icon="✅")
                    st.caption(f"Role: {role} | Purpose: {purpose}")

    # ── Control hierarchy legend ───────────────────────────────
    st.divider()
    st.markdown("**Control Hierarchy:**")
    controls = [
        ("1", "RBAC — Role Authorization"),
        ("2", "Purpose-of-Use Validation"),
        ("3", "BAA Vendor Registry"),
        ("4", "PHI Content Scan"),
        ("5", "Sensitivity Tier Check"),
        ("6", "Minimum Necessary"),
    ]
    for num, label in controls:
        st.caption(f"`{num}` {label}")

# ── Column 3: Audit log ────────────────────────────────────────
with col_audit:
    st.markdown("#### 📋 HIPAA Audit Log")

    audit_logger: AuditLogger = st.session_state.get("audit_logger")
    if audit_logger:
        summary = audit_logger.compliance_summary()
        total = summary["total_events"]
        blocked = summary["blocked_events"]
        allowed = summary["allowed_events"]

        # Metrics row
        m1, m2, m3 = st.columns(3)
        with m1:
            st.metric("Total", total)
        with m2:
            st.metric("Allowed", allowed, delta=None)
        with m3:
            st.metric("Blocked", blocked, delta=None)

        if total > 0:
            st.caption(f"Compliance rate: {summary['compliance_rate']}")

        st.divider()

        events_list = list(reversed(audit_logger.events))
        if not events_list:
            st.info("No audit events yet.", icon="📋")
        else:
            for event in events_list[:15]:  # show most recent 15
                outcome_icon = {"SUCCESS": "✅", "BLOCKED": "🚫", "WARNING": "⚠️", "ERROR": "❌"}.get(event.outcome, "ℹ️")
                label = f"{outcome_icon} {event.timestamp[-8:]} · {event.category} · {event.tool_name}"

                with st.expander(label, expanded=False):
                    st.markdown(f"**Event ID:** `{event.event_id}`")
                    st.markdown(f"**Category:** `{event.category}`")
                    st.markdown(f"**Outcome:** `{event.outcome}`")
                    st.markdown(f"**Actor:** `{event.actor_id}` ({event.actor_role})")
                    st.markdown(f"**Tool:** `{event.tool_name}`")
                    st.markdown(f"**Purpose:** `{event.purpose_of_use}`")
                    if event.patient_id:
                        st.markdown(f"**Patient Ref:** `{event.patient_id}`")
                    if event.vendor_id:
                        st.markdown(f"**Vendor:** `{event.vendor_id}`")
                    if event.policy_rule_triggered:
                        st.markdown(f"**Rule Triggered:** `{event.policy_rule_triggered}`")
                    if event.denial_reason:
                        st.error(f"**Denial Reason:** {event.denial_reason}", icon="🚫")
                    if event.phi_types_detected:
                        st.markdown(f"**PHI Detected:** `{event.phi_types_detected}`")
                    if event.risk_score > 0:
                        st.markdown(f"**Risk Score:** `{event.risk_score:.2f}`")
                    if event.justification:
                        st.caption(f"Justification: {event.justification}")

        if total > 15:
            st.caption(f"Showing 15 of {total} events.")

# ══════════════════════════════════════════════════════════════
# EVAL RUNNER (bottom section)
# ══════════════════════════════════════════════════════════════
st.divider()
with st.expander("🧪 Guardrail Eval Runner — Test Policy Logic Without LLM", expanded=False):
    st.markdown("""
    Run the deterministic eval suite directly against the policy engine.
    These tests verify guardrail logic — **no AI model is called, no API credits consumed.**
    This is how you demonstrate that your guardrails are testable and not just vibe-based prompting.
    """)
    
    if st.button("▶ Run All Eval Cases", type="secondary"):
        from app.evals.eval_cases import EVAL_CASES
        from app.guardrails.steering_handler import HIPAASteeringHandler
        from app.guardrails.audit_logger import AuditLogger
        from app.data.patients import PATIENT_DB
        from app.data.vendors import VENDOR_REGISTRY, BLOCKED_PLATFORMS
        from app.policies.rbac import get_policy, can_access_record
        from app.policies.purpose_of_use import validate_purpose
        from app.guardrails.phi_detector import detect_phi, should_block

        results = []
        for case in EVAL_CASES:
            # Deterministic policy evaluation (no agent, no LLM)
            actual_outcome = "ALLOWED"
            actual_rule = None

            tool = case.tool_name
            inputs = case.tool_inputs
            role = case.role
            purpose = case.purpose
            justification = case.justification

            policy = get_policy(role)

            # Simulate the steering handler checks
            if tool == "query_patient_record":
                if not policy.can_query_records:
                    actual_outcome = "BLOCKED"
                    actual_rule = "RBAC: Record Access Denied"
                elif role in ("it_admin", "external_auditor"):
                    actual_outcome = "BLOCKED"
                    actual_rule = "RBAC: Role Not Authorized"
                else:
                    patient_id = inputs.get("patient_id", "")
                    if patient_id in PATIENT_DB:
                        patient = PATIENT_DB[patient_id]
                        accessible, reason = can_access_record(role, patient.sensitivity)
                        if not accessible:
                            actual_outcome = "BLOCKED"
                            actual_rule = "Sensitivity Tier: Access Denied"
                    pou_valid, _ = validate_purpose(role, purpose, justification)
                    if not pou_valid and actual_outcome == "ALLOWED":
                        actual_outcome = "BLOCKED"
                        actual_rule = "Purpose-of-Use Violation"

            elif tool == "log_clinical_note":
                if role == "billing_staff":
                    actual_outcome = "BLOCKED"
                    actual_rule = "RBAC: Billing Cannot Log Clinical Notes"
                elif role in ("it_admin", "external_auditor"):
                    actual_outcome = "BLOCKED"
                    actual_rule = "RBAC: Role Not Authorized"

            elif tool == "send_data_to_vendor":
                vendor_id = inputs.get("vendor_id", "")
                if vendor_id in BLOCKED_PLATFORMS:
                    actual_outcome = "BLOCKED"
                    actual_rule = "BAA: Blocked Consumer Platform"
                elif vendor_id not in VENDOR_REGISTRY:
                    actual_outcome = "BLOCKED"
                    actual_rule = "BAA: Unregistered Vendor"
                else:
                    vendor = VENDOR_REGISTRY[vendor_id]
                    patient_id = inputs.get("patient_id", "")
                    if patient_id in PATIENT_DB:
                        patient = PATIENT_DB[patient_id]
                        if patient.sensitivity not in vendor.allowed_sensitivity:
                            actual_outcome = "BLOCKED"
                            actual_rule = "BAA: Sensitivity Tier Mismatch"
                    if actual_outcome == "ALLOWED":
                        data = inputs.get("data", "")
                        detection = detect_phi(data)
                        if should_block(detection):
                            actual_outcome = "BLOCKED"
                            actual_rule = "PHI Output Filter: Raw PHI Detected"

            elif tool == "get_deidentified_summary":
                pou_valid, _ = validate_purpose(role, purpose, justification)
                if not pou_valid:
                    actual_outcome = "BLOCKED"
                    actual_rule = "Purpose-of-Use Violation"

            passed = (actual_outcome == case.expected_outcome)
            results.append({
                "case": case,
                "actual_outcome": actual_outcome,
                "actual_rule": actual_rule,
                "passed": passed,
            })

        # Display results
        passed_count = sum(1 for r in results if r["passed"])
        total_count = len(results)
        edge_count = sum(1 for r in results if r["case"].edge_case)

        col_a, col_b, col_c = st.columns(3)
        with col_a:
            st.metric("Cases Run", total_count)
        with col_b:
            st.metric("Passed", passed_count)
        with col_c:
            st.metric("Failed", total_count - passed_count)

        st.caption(f"Edge cases (intentional): {edge_count} — these document known regex limitations, not bugs.")

        st.markdown("---")
        for r in results:
            case = r["case"]
            icon = "✅" if r["passed"] else "❌"
            edge_tag = " · ⚗️ EDGE CASE" if case.edge_case else ""
            label = f"{icon} {case.case_id} — {case.description}{edge_tag}"
            with st.expander(label, expanded=not r["passed"]):
                col1, col2 = st.columns(2)
                with col1:
                    st.caption(f"**Expected:** {case.expected_outcome}")
                    st.caption(f"**Actual:** {r['actual_outcome']}")
                    if case.expected_rule:
                        st.caption(f"**Expected Rule:** {case.expected_rule}")
                    if r['actual_rule']:
                        st.caption(f"**Actual Rule:** {r['actual_rule']}")
                with col2:
                    st.caption(f"**Role:** {case.role} | **Purpose:** {case.purpose}")
                    st.caption(f"**Tool:** {case.tool_name}")
                st.markdown(f"*{case.rationale}*")
                if not r["passed"]:
                    st.error("TEST FAILED — policy logic may need review", icon="❌")

# ── Footer ─────────────────────────────────────────────────────
st.divider()
st.caption(
    "Strands PHI Guardrails Demo v2 · Built by Noah Mills · Healthcare AI Security Portfolio · "
    "All patient data is simulated. No real PHI is processed. "
    "HIPAA controls implemented via Strands Agents SDK SteeringHandler — deterministic, not prompt-only."
)
