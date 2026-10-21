"""Verity dashboard: watch what your AI is doing in production."""
import hmac
import json
import os

import streamlit as st

from verity.store import init_db, recent_traces

st.set_page_config(page_title="Verity dashboard", layout="wide")

# Password gate (audit F1): traces contain raw prompts and answers, so a
# deployed dashboard must never render them without a login. Set
# VERITY_DASHBOARD_PASSWORD before deploying this app anywhere. Local
# use without a password still works — but says so, loudly.
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
else:
    st.warning(
        "VERITY_DASHBOARD_PASSWORD is not set: anyone who can reach this "
        "dashboard can read every trace, including raw prompts. Set it "
        "before deploying the dashboard anywhere.")

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
