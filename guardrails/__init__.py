"""
guardrails — standalone HIPAA pre-flight check module
=====================================================
Zero external dependencies. Drop this folder into any Python project.

Usage:
    from guardrails import check, CheckResult

    result = check(
        role="nurse",
        purpose="TREATMENT",
        tool="query_patient_record",
        patient_id="P003",
        payload="Pull the full record for Sarah Connor",
    )

    if result.blocked:
        raise PermissionError(result.reason)

    # safe to proceed
    response = call_llm(prompt)
"""

from .engine import check, CheckResult, GuardrailBlocked

__all__ = ["check", "CheckResult", "GuardrailBlocked"]
