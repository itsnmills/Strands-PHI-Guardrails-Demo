# Practice-Friendly Naming Map

For the installed preflight layer during a Velari AI Use Readiness engagement. The engine's internal names stay the same; the exposure layer presents real practice English.

## Roles

| engine name | practice-facing label |
|--------------|----------------------|
| physician      | Provider |
| nurse          | Clinical Staff |
| billing_staff  | Billing / Front Desk |
| researcher     | Research Team |
| it_admin       | IT / MSP Admin |
| external_auditor | External Reviewer |

## Purposes

| engine name | practice-facing label |
|-------------|----------------------|
| TREATMENT    | Patient care |
| PAYMENT      | Billing, claims, insurance |
| OPERATIONS   | Running the practice |
| RESEARCH     | Study, registry, quality project |
| LEGAL        | Legal or counsel request |
| PUBLIC_HEALTH| Public health reporting |
| HANDOFF      | Shift handoff or coverage |
| AUDIT        | Records audit |

## Tools

| engine name | practice-facing label |
|-------------|----------------------|
| query_patient_record       | Look up a patient record |
| get_deidentified_summary   | Get a de-identified summary |
| check_vendor_baa_status    | Check a vendor's BAA status |
| send_data_to_vendor        | Send data to an outside tool |
| log_clinical_note          | Add a note to the chart |
| call_llm                   | Ask an AI assistant |

## Vendors (starter set for the preflight demo)

| engine name | practice-facing label |
|-------------|----------------------|
| internal                  | Practice systems only |
| epic / cerner             | EHR |
| azure-openai              | Microsoft Copilot inside our tenant |
| aws-bedrock               | Approved HIPAA-ready AI vendor |
| change-healthcare         | Approved billing/claims vendor |
| chatgpt / claude / gemini | Consumer AI (blocked without special setup) |
| slack                     | Consumer messaging (blocked) |

## The Rulebook Questions (what staff answer before pushing AI through)

1. Which system is the data coming from (EHR, portal, billing, phone, laptop)?
2. Which tool is this going to (exact name, not "the AI thing")?
3. Does that tool have a signed BAA with our practice?
4. Is anything identifiable in this content (any name, date of birth, address, SSN, phone, or MRN)?
5. Am I authorized to share this with that tool?

An escalation answer of "I'm not sure" routes to the practice manager before sending. Each of these maps cleanly to a CheckResult or a Jev Score/Noul answer; no patient text ever crosses to the model.
