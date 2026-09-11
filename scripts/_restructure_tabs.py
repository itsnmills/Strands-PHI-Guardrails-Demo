"""One-off structural edit: move audit content under tab_audit, insert traffic terminal tab."""
import sys

SRC = "streamlit_app.py"
src = open(SRC).read()
lines = src.split("\n")

# 1. Locate the audit content block (runs from 'total = len(events)' to the 'Showing 15 of' caption)
start = next(i for i, l in enumerate(lines) if l == "    total = len(events)")
cap_idx = next(i for i, l in enumerate(lines)
               if l.startswith('        st.caption(f"Showing 15 of {total} events'))
assert start < cap_idx

# 2. Re-indent that block by 4 spaces (it moves under `with tab_audit:`)
for i in range(start, cap_idx + 1):
    if lines[i].strip():
        lines[i] = "    " + lines[i]

# 3. Insert the stat-chips row right after the dist bar line
dist_idx = next(i for i, l in enumerate(lines)
                if 'st.markdown(f\'<div class="dist">{seg}</div>\'' in l)
stat_chips = """        phi_n = sum(1 for e in events if e.get("phi_types_detected"))
        anom = st.session_state.session_monitor.anomaly_count
        bgc = len(st.session_state.break_glass.pending_review())
        st.markdown(
            '<div class="statchips">'
            + f'<span class="statchip{" hot" if bgc else ""}">break-glass <b>{bgc}</b></span>'
            + f'<span class="statchip">velocity anomalies <b>{anom}</b></span>'
            + f'<span class="statchip">phi-flagged <b>{phi_n}</b></span>'
            + "</div>", unsafe_allow_html=True)"""
lines[dist_idx + 1:dist_idx + 1] = stat_chips.split("\n")
cap_idx = next(i for i, l in enumerate(lines)
               if l.strip().startswith('st.caption(f"Showing 15 of {total} events'))

# 4. Fix the expander head: plain text (HTML never rendered in expander labels) + category + chain
for i, l in enumerate(lines):
    if l.strip().startswith("chain_bit = f' · <span"):
        lines[i] = '        chain_bit = f" · ⛓ {e[\'entry_hash\'][:8]}" if e.get("entry_hash") else ""'
    if l.strip().startswith('head = f"{cls} {e[\'tool_name\']} · {e[\'timestamp\'][11:19]}{chain_bit}"'):
        lines[i] = ('        head = f"{cls} {e[\'tool_name\']} · {e[\'category\'].lower()} · '
                    '{e[\'timestamp\'][11:19]}{chain_bit}"')
cap_idx = next(i for i, l in enumerate(lines)
               if l.strip().startswith('st.caption(f"Showing 15 of {total} events'))

# 5. Insert the traffic terminal tab after the audit content
traffic_tab = '''    with tab_traffic:
        recs = st.session_state.traffic
        st.caption("Everything sent to and received from the model — full-fidelity request messages, streaming chunks, usage and latency. No black box.")
        lines = []
        for r in reversed(recs[-14:]):
            stl = r.get("status", "?")
            arrow = {"requesting": "→", "streaming": "⇄", "complete": "←", "error": "✕"}.get(stl, "·")
            dcls = {"requesting": "req", "complete": "res", "error": "err"}.get(stl, "dim")
            lat = f"{r['latency_ms']:.0f}ms" if r.get("latency_ms") is not None else "—"
            u = r.get("usage")
            tok = f"{u['total']} tok" if u else "—"
            lines.append(
                f'<div class="tl"><span class="tdir {dcls}">{arrow}</span>'
                f'<span class="ttime">{r["ts"]}</span><span class="tmod">{r["model"]}</span>'
                f'<span class="tstat {"err" if stl == "error" else ""}">{stl}</span>'
                f'<span class="tbit">{lat}</span><span class="tbit">{tok}</span></div>'
            )
        if lines:
            st.markdown('<div class="term">' + "".join(lines) + "</div>", unsafe_allow_html=True)
        else:
            st.markdown('<div class="term"><div class="tl"><span class="tdir dim">▍</span>'
                        '<span class="ttime">waiting for the first live run…</span></div></div>', unsafe_allow_html=True)
        for r in reversed(recs[-14:]):
            head = f'{r["ts"]} · {r["model"]} · {r.get("status")}' + (
                f" · {r['latency_ms']:.0f}ms" if r.get("latency_ms") is not None else "")
            with st.expander(head, expanded=False):
                st.caption("REQUEST — messages exactly as sent (system prompt, session context, tool intent)")
                st.code(json.dumps(r["request_messages"], indent=2)[:9000], language="json")
                if r.get("status") == "error":
                    st.error(r.get("error") or "request failed")
                else:
                    if r.get("stream_reasoning"):
                        with st.expander("reasoning stream", expanded=False):
                            st.code(r["stream_reasoning"][:4000], language=None)
                    text = r.get("stream_text") or r.get("final_text")
                    if text:
                        st.caption("RESPONSE — accumulated stream output")
                        st.code(text[:6000], language=None)
                    else:
                        st.caption("no text content captured")
                    if r.get("usage"):
                        st.caption(f"usage · prompt {r['usage'].get('prompt')} / completion {r['usage'].get('completion')} "
                                   f"/ total {r['usage'].get('total')} tokens · latency {r.get('latency_ms')} ms")
'''
lines[cap_idx + 1:cap_idx + 1] = traffic_tab.split("\n")

open(SRC, "w").write("\n".join(lines))
print("transformation applied")
