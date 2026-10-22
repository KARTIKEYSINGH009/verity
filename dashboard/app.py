"""Verity dashboard: watch what your AI is doing in production."""
import hmac
import json
import os

import streamlit as st

from verity.store import init_db, recent_traces

st.set_page_config(page_title="Verity dashboard", layout="wide")

# Password gate (audit F1, hardened in batch 2 / finding 3): traces
# contain raw prompts and answers, so this dashboard must never render
# them without a login. It now FAILS CLOSED: with no
# VERITY_DASHBOARD_PASSWORD set it refuses to display anything, unless
# the operator explicitly opts into unauthenticated local use with
# VERITY_DASHBOARD_ALLOW_UNAUTHENTICATED=true.
_DASHBOARD_PASSWORD = os.getenv("VERITY_DASHBOARD_PASSWORD", "")
if _DASHBOARD_PASSWORD:
    if not st.session_state.get("verity_authed"):
        st.title("Verity — AI firewall dashboard")
        _pw = st.text_input("Dashboard password", type="password")
        if _pw:
            if hmac.compare_digest(_pw, _DASHBOARD_PASSWORD):
                st.session_state["verity_authed"] = True
                st.rerun()
            st.error("Incorrect password")
        st.stop()
elif os.getenv("VERITY_DASHBOARD_ALLOW_UNAUTHENTICATED",
               "").lower() == "true":
    st.warning(
        "VERITY_DASHBOARD_PASSWORD is not set and unauthenticated use "
        "was explicitly allowed (VERITY_DASHBOARD_ALLOW_UNAUTHENTICATED)"
        ": anyone who can reach this dashboard can read every trace, "
        "including raw prompts. Local use only — never deploy this way.")
else:
    st.error(
        "VERITY_DASHBOARD_PASSWORD is not set, so this dashboard is "
        "refusing to display traces. Set a password before using it, or "
        "set VERITY_DASHBOARD_ALLOW_UNAUTHENTICATED=true for local-only "
        "use.")
    st.stop()

st.title("Verity — AI firewall dashboard")

init_db()
traces = recent_traces(100)

col1, col2, col3 = st.columns(3)
col1.metric("Requests traced", len(traces))
col2.metric("Blocked by guard", sum(t["blocked"] for t in traces))
col3.metric("Hallucination flags",
            sum("hallucination_risk" in json.loads(t["flags_json"])
                for t in traces))

st.subheader("Recent traces")
for t in traces:
    flags = json.loads(t["flags_json"])
    label = f"#{t['id']} · {t['model']} · {'BLOCKED' if t['blocked'] else 'ok'}"
    if flags:
        label += f" · {', '.join(flags)}"
    with st.expander(label):
        st.markdown("**Input**")
        st.code(t["input_text"][:2000])
        st.markdown("**Output**")
        st.code(t["output_text"][:2000])
        if t["faithfulness"] is not None:
            st.progress(t["faithfulness"], text=f"faithfulness {t['faithfulness']}")
