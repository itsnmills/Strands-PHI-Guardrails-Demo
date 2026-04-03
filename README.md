# Strands PHI Guardrails Demo
### Healthcare AI Security · HIPAA Policy Enforcement · Strands Agents SDK

> **Portfolio project by Noah Mills** — Healthcare IT / Cybersecurity / AI Governance  

## 🔴 Live Interactive Demo

**[▶ Launch PHI Guardrails Demo](https://www.perplexity.ai/computer/a/strands-phi-guardrails-healthc-lFAE5fEOTiC0T4CvehvmkQ)** — Full interactive browser demo, no install required. Click any of 11 scenarios to see real-time HIPAA policy enforcement.

![PHI Guardrails Demo UI v2 — Nurse blocked from accessing RESTRICTED psychiatric record](screenshot-ui-v2.jpg)
> Demonstrates: RBAC, Purpose-of-Use enforcement, PHI detection, BAA verification, sensitivity tiers, structured audit logging, and eval-driven policy testing — all implemented as deterministic code, not prompt-only safety.

---

## The Problem

Healthcare AI systems are increasingly integrated into clinical workflows — summarizing records, routing data, generating documentation. But most implementations treat safety as an afterthought: a system prompt saying "don't share PHI" and hoping the model complies.

**That is not HIPAA compliance. That is vibe-based security.**

Real healthcare AI security requires:
- **Deterministic controls** that cannot be bypassed by prompt injection
- **Role-based access enforcement** that reflects clinical job families (nurses ≠ physicians ≠ billing staff)
- **Purpose-of-use validation** to enforce HIPAA's minimum necessary standard
- **Sensitivity classification** for special categories (psychiatric, substance use, HIV)
- **Immutable audit logging** that satisfies 45 CFR Part 164 requirements
- **BAA registry enforcement** before any external data transmission

This project demonstrates all of the above using the **Strands Agents SDK** and its `SteeringHandler` pre-tool interception pattern.

---

## What This Project Demonstrates

| Capability | Implementation |
|---|---|
| Pre-tool guardrail interception | Strands `SteeringHandler.steer_before_tool()` |
| Role-Based Access Control (RBAC) | Policy matrix across 6 clinical role types |
| Purpose-of-Use enforcement | 8 HIPAA PoU codes with role-scoped validation |
| PHI detection with confidence scoring | Regex + confidence weighting, risk score threshold |
| Sensitivity tier enforcement | STANDARD / SENSITIVE / RESTRICTED classification |
| BAA vendor registry | Allowlist with tier-scoped sensitivity constraints |
| Structured audit logging | HIPAA §164.312(b) compliant event schema |
| Eval-driven policy testing | 16 test cases — deterministic, no LLM required |
| False-positive mitigation | Confidence-weighted scoring vs binary regex |

---

## Architecture

```
Strands-PHI-Guardrails-Demo/
├── streamlit_app.py              ← Main UI (role selector, 3-column layout, eval runner)
├── app/
│   ├── agent/
│   │   └── factory.py            ← Role-scoped agent construction
│   ├── guardrails/
│   │   ├── steering_handler.py   ← Core: pre-tool HIPAA policy enforcement
│   │   ├── phi_detector.py       ← PHI detection with confidence scoring
│   │   └── audit_logger.py       ← Structured HIPAA audit event logging
│   ├── policies/
│   │   ├── rbac.py               ← Role policy matrix (6 roles × 8 capabilities)
│   │   └── purpose_of_use.py     ← HIPAA PoU code validation
│   ├── tools/
│   │   └── clinical_tools.py     ← Strands tool definitions (happy path)
│   ├── data/
│   │   ├── patients.py           ← Simulated patients with sensitivity labels
│   │   └── vendors.py            ← BAA registry with tier constraints
│   └── evals/
│       └── eval_cases.py         ← 16 eval cases with expected outcomes
├── tests/
│   └── test_evals.py             ← pytest test runner for eval cases
├── .env.example
└── requirements.txt
```

### Control Flow

```
User Prompt
    │
    ▼
Strands Agent (LLM)
    │  selects tool
    ▼
HIPAASteeringHandler.steer_before_tool()   ← DETERMINISTIC — runs before the LLM result matters
    │
    ├─ 1. RBAC: Does this role have permission?
    ├─ 2. Purpose-of-Use: Is the declared purpose valid for this role?
    ├─ 3. Sensitivity Tier: Can this role access this patient's data class?
    ├─ 4. BAA Vendor Check: Is the destination in the registry?
    ├─ 5. PHI Content Scan: Does the payload contain raw PHI?
    └─ 6. Sensitivity × Vendor Match: Does BAA scope cover this data tier?
         │
         ├─ Any check fails → Guide(reason=...) → Agent generates denial response
         │                    AuditLogger records BLOCKED event
         │
         └─ All checks pass → Proceed() → Tool executes
                               AuditLogger records SUCCESS event
```

---

## Security Features

### RBAC Policy Matrix

| Role | Query Records | SENSITIVE | RESTRICTED | Send to Vendors | Log Notes |
|---|---|---|---|---|---|
| Physician | ✅ | ✅ | ✅ | ✅ | ✅ |
| Nurse | ✅ | ✅ | ❌ | ❌ | ✅ |
| Billing Staff | ✅ (billing only) | ❌ | ❌ | ✅ (billing only) | ❌ |
| Researcher | ❌ | ❌ | ❌ | ❌ | ❌ |
| IT Admin | ❌ | ❌ | ❌ | ❌ | ❌ |
| External Auditor | ❌ | ❌ | ❌ | ❌ | ❌ |

### Patient Sensitivity Tiers

| Tier | What It Covers | Example in Demo |
|---|---|---|
| STANDARD | Routine clinical data | P001 (Diabetes), P004 (Oncology) |
| SENSITIVE | Substance use, HIV, reproductive | P002 (Opioid Use Disorder) |
| RESTRICTED | Psychiatric, genetic info | P003 (Major Depressive Disorder) |

Nurses cannot access RESTRICTED records. Billing staff cannot access SENSITIVE or RESTRICTED data. AI vendors (Azure OpenAI, AWS Bedrock) are BAA-scoped to STANDARD data only.

### PHI Detection — Confidence Scoring

Naive regex PHI detection produces excessive false positives (zip codes in version numbers, names that match `[A-Z][a-z]+ [A-Z][a-z]+`). This project addresses that with confidence-weighted scoring:

| Pattern | Confidence | Notes |
|---|---|---|
| SSN (`xxx-xx-xxxx`) | 0.97 | Very specific format |
| Labeled MRN | 0.95 | Requires `MRN:` prefix |
| Email address | 0.90 | Standard regex, low FP |
| US phone number | 0.87 | 10-digit patterns |
| Zip code | 0.35 | Very noisy — many non-PHI 5-digit numbers |
| Full name pattern | 0.55 | High false positive risk |

A payload is blocked only if `max(confidence scores) >= 0.60`. This reduces zip code and name false positives significantly.

**Known limitation (documented in evals):** PHI written in natural language ("patient born in March eighty-five") evades all regex-based detection. In production, this would be layered with [AWS Comprehend Medical](https://aws.amazon.com/comprehend/medical/) or [Microsoft Presidio](https://microsoft.github.io/presidio/) NER models.

### Audit Log Schema

Every guardrail decision produces a structured event compatible with SIEM ingestion:

```json
{
  "event_id": "a3f8b1c2",
  "timestamp": "2026-04-03T20:15:33Z",
  "category": "POLICY_EVAL",
  "outcome": "BLOCKED",
  "actor_role": "nurse",
  "actor_id": "USER-001",
  "tool_name": "query_patient_record",
  "action_description": "BLOCKED by rule: Sensitivity Tier: Access Denied",
  "patient_id": "P003",
  "policy_rule_triggered": "Sensitivity Tier: Access Denied",
  "denial_reason": "Role 'nurse' is not authorized to access RESTRICTED records...",
  "phi_types_detected": [],
  "risk_score": 0.0,
  "purpose_of_use": "TREATMENT",
  "justification": ""
}
```

---

## Demo Scenarios

| Scenario | Role | Purpose | Expected | What It Shows |
|---|---|---|---|---|
| Physician queries patient P001 | physician | TREATMENT | ✅ ALLOWED | Normal clinical access |
| Nurse gets handoff summary | nurse | HANDOFF | ✅ ALLOWED | Minimum necessary for care transition |
| Researcher gets de-identified data | researcher | RESEARCH | ✅ ALLOWED | Research with IRB justification |
| Billing sends claims to processor | billing_staff | PAYMENT | ✅ ALLOWED | Billing workflow, no clinical data |
| PHI sent to Slack | physician | TREATMENT | 🚫 BLOCKED | BAA: Blocked consumer platform |
| Nurse accesses psychiatric record | nurse | TREATMENT | 🚫 BLOCKED | Sensitivity tier enforcement |
| Researcher queries raw record | researcher | RESEARCH | 🚫 BLOCKED | RBAC: no raw record access for researchers |
| Raw PHI sent to AI vendor | physician | TREATMENT | 🚫 BLOCKED | PHI content scan |
| Unknown vendor | physician | TREATMENT | 🚫 BLOCKED | BAA: unregistered vendor |
| IT admin queries patient | it_admin | OPERATIONS | 🚫 BLOCKED | RBAC: system roles have zero PHI access |
| Natural language PHI (edge case) | physician | TREATMENT | ⚠️ ALLOWED | Documents regex detection gap |

---

## Eval Strategy

The project includes 16 eval cases in `app/evals/eval_cases.py` that test the policy engine **without calling any LLM**. This is important because:

1. Guardrail correctness should not depend on model behavior
2. Evals can run in CI with no API credits
3. Regressions in policy logic are caught immediately

```bash
# Run policy evals (no LLM, no API key needed)
pytest tests/test_evals.py -v

# Or from the Streamlit UI: click "Run All Eval Cases"
```

Eval cases include intentional edge cases that document known limitations — demonstrating that you understand the boundaries of regex-only PHI detection and what production mitigation would look like.

---

## Setup

```bash
# Clone and set up
git clone https://github.com/itsnmills/Strands-PHI-Guardrails-Demo
cd Strands-PHI-Guardrails-Demo

python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env — add your OpenRouter API key

# Run
streamlit run streamlit_app.py
```

### Requirements

```
strands-agents
python-dotenv
streamlit
pytest
```

An OpenRouter API key is required for LLM calls. The eval runner works without any API key.

---

## Why This Matters for Healthcare Cybersecurity

Healthcare is the most targeted sector for ransomware and data breaches (HHS, 2024). AI integration dramatically expands the attack surface — every LLM agent that touches PHI is a potential vector for exfiltration, privilege escalation, or compliance violation.

The controls demonstrated in this project map directly to:
- **HIPAA Security Rule** — §164.308(a)(4) Access Controls, §164.312(b) Audit Controls
- **NIST SP 800-66r2** — Implementing the HIPAA Security Rule
- **HITRUST CSF** — Control categories 01.a–01.d (Access Control)
- **CMS MARS-E** — Minimum Acceptable Risk Standards for Exchanges
- **Zero Trust principles** — Never trust, always verify, log everything

This is not a production system. It is a working demonstration of the principles that production healthcare AI security systems must implement.

---

## Author

**Noah Mills** — Healthcare IT / Cybersecurity / AI Governance  
[GitHub: itsnmills](https://github.com/itsnmills) · St. Louis, MO  
Building at the intersection of AI agents, cloud security, and healthcare compliance.
