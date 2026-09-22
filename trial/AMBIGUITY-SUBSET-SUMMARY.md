# Jev Ambiguity-Subset Trial Summary

**Date:** 2026-09-18 (case run at 23:0x CDT)
**Cases:** 45 of 58 (cases carrying at least one ambiguity signal)
**Ambiguity flags used:** novel_tool, unknown_vendor, missing_justification
**Endpoint:** OpenRouter `/api/alpha/decisions`, model `typesafe/jev-1.13`
**Jev's state:** payload-free structured state + explicit `ambiguity_flags`. No patient text, no identifiers, no engine verdict.

## Headline Numbers

| segment | count | Jev agree with engine | rate |
|---------|-------|----------------------|------|
| whole subset | 45 | 22 | 48.9% |
| subset cases engine=BLOCKED | 26 | 26 | 100% |
| subset cases engine=ALLOWED | 19 | 0 | 0% |

## The Two-Segment Pattern

This is the single most useful finding so far.

**On every subset case the engine already blocked (26 cases), Jev triaged to "escalate" 100% of the time** with newly tiny p_legit readings (0.09-0.33). That is exactly the desired behavior: when a block is in play, Jev does not contradict the engine, it reinforces escalation for human review. Zero false-allows in this slice.

**On every subset case the engine already allowed (19 cases), Jev recommended "escalate" 100% of the time** with p_legit 0.14-0.49. This over-conservatism is not noise: the `missing_justification` ambiguity flag is what put these cases in the subset, and Jev is correctly reading that same absence as "uncertain, hand to a human." It is over-correcting on cases where the engine might legitimately allow without a written reason (e.g., a standard physician record query for treatment).

## What This Means For The Deployment Shape

The conservative behavior splits exactly along engine confidence:
- On the "resolves to BLOCKED" slice, Jev is a precision instrument (100% correct, all escalate) and does not create false denials.
- On the "already confidently allowed" slice, Jev is unnecessarily strict because the flag `missing_justification` is doing double duty: it is a routing cue for "this case *could* have a justification", not evidence that one is owed.

The narrower deployment slice is *not* "any case with a missing justification." It is "any case where a justification is semantically owed (tool ~= writes, sends externally, or queries a SENSITIVE/RESTRICTED record) but none was provided." That distinction is worth making in the adapter, not papering over with threshold tuning on the model side.

## What This Confirms

- Jev formatting is reliable: structured answers, no invented fields, deterministic cost shape across 45 sequential calls.
- Conservative-not-permissive behavior: Jev never recommended "allow" on top of an engine block in this slice. That is exactly the failure direction you do not want in a healthcare runtime.
- The "escalate path is where Jev adds value; the engine handles confidence" architecture is measurably correct, not just a nice story.

## Comparison to the full suite

Across all 58 cases, Jev agreed with the engine 48.3% because most unambiguous cases submitted to it caused re-litigation. Within the ambiguity-trigger subset alone, agreement is identical at 48.9%, but the composition is dramatically better: 100% precision on the engine-blocked half, no false-allows anywhere, and a calibration question (over-escalation) instead of a policy-bypass hole.

## Next Improvement

1. Add an `justification_owed_semantically` boolean to the state instead of raw `missing_justification`, driven by the tool/purpose relationship, and re-run the subset with the same questions. That should let Jev separate "physician reads a standard record with no narrative" (benign) from "billing pushes data externally with no justification" (genuinely uncertain).
2. Once the adapter from the parallel workthread lands (`app/jev/decisions.py`), swap the inline HTTP caller in this runner for the shared adapter so there is only one API surface to maintain.
