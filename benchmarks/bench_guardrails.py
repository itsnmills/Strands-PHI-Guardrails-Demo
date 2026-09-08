"""
benchmarks/bench_guardrails.py
─────────────────────────────
Guardrail overhead benchmark.

The question a reviewer actually has: what does pre-tool enforcement COST?
Run from the repo root:

    .venv/bin/python benchmarks/bench_guardrails.py

Measures, with time.perf_counter_ns over many iterations:
  1. evaluate()               — the deterministic six-control engine
  2. evaluate() + monitor     — with session-velocity + break-glass state
  3. detect_phi()             — the PHI scanner alone, per payload class
  4. audit log() + verify     — HMAC chain seal and full-chain verification
  5. steer_before_tool()      — the live-agent pre-tool hook round-trip
                                (includes asyncio.run overhead, noted)

Writes benchmarks/results.json so README numbers are reproducible.
"""

import asyncio
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from app.guardrails.policy_engine import evaluate
from app.guardrails.phi_detector import detect_phi
from app.guardrails.audit_logger import AuditLogger
from app.guardrails.session_monitor import SessionMonitor
from app.evals.eval_cases import EVAL_CASES
from app.evals.redteam_cases import REDTEAM_CASES
from app.data.patients import PATIENT_DB

N_EVAL = 5000        # iterations per engine measurement
N_DETECT = 20000     # iterations per payload
N_AUDIT = 5000


def percentile(sorted_vals: list[int], p: float) -> float:
    idx = min(len(sorted_vals) - 1, int(round(p / 100 * (len(sorted_vals) - 1))))
    return sorted_vals[idx]


def stats_ns(samples: list[int]) -> dict:
    s = sorted(samples)
    return {
        "p50_us": round(percentile(s, 50) / 1000, 2),
        "p95_us": round(percentile(s, 95) / 1000, 2),
        "p99_us": round(percentile(s, 99) / 1000, 2),
        "mean_us": round(statistics.fmean(s) / 1000, 2),
        "n": len(s),
    }


def bench_engine() -> dict:
    samples = []
    for _ in range(N_EVAL):
        for c in EVAL_CASES:
            t0 = time.perf_counter_ns()
            evaluate(role=c.role, purpose=c.purpose, justification=c.justification,
                     tool_name=c.tool_name, tool_inputs=dict(c.tool_inputs))
            samples.append(time.perf_counter_ns() - t0)
    return stats_ns(samples)


def bench_engine_stateful() -> dict:
    monitor = SessionMonitor()
    bg = __import__("app.policies.break_glass", fromlist=["BreakGlassRegistry"]).BreakGlassRegistry()
    bg.grant("nurse", "P003", "Psych emergency consult, attending unavailable, immediate review required")
    cases = [(c, dict(c.tool_inputs)) for c in EVAL_CASES if c.tool_name in ("query_patient_record", "send_data_to_vendor")]
    samples = []
    i = 0
    for _ in range(N_EVAL):
        for c, inputs in cases:
            i += 1
            if i % 220 == 0:
                monitor.reset()  # realistic window occupancy: dozens of accesses per 5-minute window
            t0 = time.perf_counter_ns()
            evaluate(role=c.role, purpose=c.purpose, justification=c.justification,
                     tool_name=c.tool_name, tool_inputs=inputs, monitor=monitor, break_glass=bg)
            samples.append(time.perf_counter_ns() - t0)
    return stats_ns(samples)


def bench_detect() -> dict:
    payloads = {
        "clean_billing": "ICD-10: E11.9, CPT: 99213, DOS: 2026-03-15",
        "clinical_note_phi": "Patient Jane Doe SSN 123-45-6789 needs insulin adjustment. Contact 314-555-0101.",
        "narrative_gap": "The patient born in March of eighty-five living on Maple in St Louis presented with elevated A1C",
        "blocked_label_dob": "birth date 03/14/1985 on file",
    }
    out = {}
    for name, payload in payloads.items():
        samples = []
        for _ in range(N_DETECT):
            t0 = time.perf_counter_ns()
            detect_phi(payload)
            samples.append(time.perf_counter_ns() - t0)
        out[name] = stats_ns(samples)
    return out


def bench_audit() -> dict:
    log_samples = []
    logger = AuditLogger()
    for i in range(N_AUDIT):
        t0 = time.perf_counter_ns()
        logger.log(category="POLICY_EVAL", outcome="SUCCESS", actor_role="physician", actor_id=f"dr-{i%9}",
                   tool_name="query_patient_record", action_description="bench", patient_id="P001")
        log_samples.append(time.perf_counter_ns() - t0)
    verify_samples = []
    for _ in range(200):
        t0 = time.perf_counter_ns()
        logger.verify_chain()
        verify_samples.append(time.perf_counter_ns() - t0)
    return {"log_event": stats_ns(log_samples),
            "verify_chain_5000": {**stats_ns(verify_samples), "note": f"full chain of {N_AUDIT} events"}}


def bench_steering() -> dict:
    from app.guardrails.steering_handler import HIPAASteeringHandler
    logger = AuditLogger()
    handler = HIPAASteeringHandler(
        role="physician", actor_id="bench-1", purpose="TREATMENT", justification="", audit_logger=logger,
    )
    tool_use = {"name": "query_patient_record", "input": {"patient_id": "P001"}}
    async def one():
        t0 = time.perf_counter_ns()
        await handler.steer_before_tool(agent=None, tool_use=dict(tool_use))
        return time.perf_counter_ns() - t0
    samples = [asyncio.run(one()) for _ in range(2000)]
    return {**stats_ns(samples), "note": "includes asyncio.run scheduling overhead"}


def main() -> None:
    print("Benchmarking guardrail overhead (no LLM, no network)…\n")
    results = {
        "engine_deterministic": bench_engine(),
        "engine_stateful_monitor_breakglass": bench_engine_stateful(),
        "phi_detection": bench_detect(),
        "audit_chain": bench_audit(),
        "steering_roundtrip": bench_steering(),
    }
    out_path = os.path.join(os.path.dirname(__file__), "results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    for section, data in results.items():
        print(f"── {section} " + "─" * max(1, 50 - len(section)))
        if isinstance(data, dict) and "p50_us" in data:
            print(f"   p50 {data['p50_us']:>8} µs · p95 {data['p95_us']:>8} µs · p99 {data['p99_us']:>8} µs · mean {data['mean_us']:>8} µs (n={data['n']})")
        else:
            for k, v in data.items():
                if isinstance(v, dict) and "p50_us" in v:
                    extra = f" — {v['note']}" if v.get("note") else ""
                    print(f"   {k:<26} p50 {v['p50_us']:>8} µs · p99 {v['p99_us']:>8} µs{extra}")
    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()
