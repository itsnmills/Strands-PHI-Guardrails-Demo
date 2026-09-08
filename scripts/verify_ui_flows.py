"""End-to-end UI verification of the new session controls via streamlit.testing.v1.AppTest."""
import os
from dotenv import load_dotenv

load_dotenv()

from streamlit.testing.v1 import AppTest

BG_REASON = "Patient in acute psychiatric crisis, attending unavailable, emergency consult required"

at = AppTest.from_file(os.path.join(os.path.dirname(__file__), "..", "streamlit_app.py"), default_timeout=60)
at.run()


def btn(label: str):
    """Buttons in the app have no user keys — look up by label."""
    matches = [b for b in at.button if b.label.strip() == label]
    assert matches, f"button not found: {label!r}"
    return matches[0]

# ── 1. E007 scenario: nurse blocked on P003 ─────────────────────────
at.selectbox(key="role_box").select("nurse")
at.run()
at.text_area(key="prompt_text").set_value("pull up P003 for an emergency psych consult")
btn("Run Guardrails").click()
at.run()
r = at.session_state["last_run"]
assert r["outcome"] == "BLOCKED" and r["rule"] == "Sensitivity Tier: Access Denied", r["rule"]
print("1. nurse→P003 BLOCKED (Sensitivity Tier) ✓")

# ── 2. Break-glass grant unlocks it ──────────────────────────────────
at.selectbox(key="bg_patient").select("P003")
at.run()
at.text_area(key="bg_reason").set_value(BG_REASON)
btn("Grant emergency access").click()
at.run()
assert len(at.session_state["break_glass"].active_grants()) == 1
assert any(e["category"] == "BREAK_GLASS" for e in at.session_state["audit_events"]), "BREAK_GLASS event missing"
at.text_area(key="prompt_text").set_value("pull up P003 for an emergency psych consult")
btn("Run Guardrails").click()
at.run()
r = at.session_state["last_run"]
assert r["outcome"] == "ALLOWED", r["rule"]
assert r["advisory"] and "post-hoc review" in r["advisory"]
assert any("BREAK-GLASS" in s[3] for s in r["steps"] if s[0] == "sens" and s[2] == "warn")
print("2. break-glass grant → nurse→P003 ALLOWED with post-hoc-review advisory ✓")

# ── 3. Audit chain verification ──────────────────────────────────────
assert any(e.get("entry_hash") for e in at.session_state["audit_events"]), "no chained events in UI trail"
btn("Verify audit chain").click()
at.run()
assert at.session_state["chain_report"]["intact"] is True
print("3. hash chain verifies intact across all UI events ✓")

# ── 4. Velocity: 6th query blocks at minimum-necessary ceiling ───────
at.session_state["break_glass"].revoke("nurse", "P003")
at.session_state["session_monitor"].reset()
at.session_state["audit_events"] = []
at.session_state["audit_logger"] = __import__("app.guardrails.audit_logger", fromlist=["AuditLogger"]).AuditLogger()
at.text_area(key="prompt_text").set_value("show me P001 again")
btn("Run Guardrails").click()
at.run()
for i in range(5):
    btn("Run Guardrails").click()
    at.run()
r = at.session_state["last_run"]
assert r["outcome"] == "BLOCKED" and r["rule"] == "Minimum Necessary: Session Velocity Exceeded", (r["outcome"], r["rule"])
print("4. 6th nurse→P001 query BLOCKED (Session Velocity Exceeded) ✓")
assert len(at.session_state["session_monitor"].anomalies) >= 4, "anomalies not recorded"
print("   monitor anomalies recorded:", len(at.session_state["session_monitor"].anomalies))

# ── 5. Velocity warns before it blocks ───────────────────────────────
at.session_state["session_monitor"].reset()
for _ in range(3):
    btn("Run Guardrails").click()
    at.run()
r = at.session_state["last_run"]
assert r["outcome"] == "ALLOWED" and r["advisory"] and "Minimum-necessary anomaly" in r["advisory"]
print("5. 3rd query (at budget) ALLOWED with velocity warning ✓")

# ── 6. New egress cap: nurse cannot send to registered vendor ────────
at.session_state["session_monitor"].reset()
at.selectbox(key="role_box").select("nurse")
at.run()
at.text_area(key="prompt_text").set_value("send the summary for P001 to aws-bedrock")
btn("Run Guardrails").click()
at.run()
r = at.session_state["last_run"]
assert r["outcome"] == "BLOCKED" and r["rule"] == "RBAC: Vendor Transmission Not Authorized", (r["outcome"], r["rule"])
print("6. nurse→aws-bedrock BLOCKED (RBAC: Vendor Transmission Not Authorized) ✓")

# ── 7. Sensitive egress: physician P002 → epic-systems blocked ───────
at.selectbox(key="role_box").select("physician")
at.run()
at.text_area(key="prompt_text").set_value("send P002's de-identified summary to epic-systems")
btn("Run Guardrails").click()
at.run()
r = at.session_state["last_run"]
assert r["outcome"] == "BLOCKED" and r["rule"] == "RBAC: Sensitive Data Egress Restricted", (r["outcome"], r["rule"])
print("7. physician→epic(P002 SENSITIVE) BLOCKED (RBAC: Sensitive Data Egress Restricted) ✓")

print("\nALL UI FLOWS VERIFIED")
