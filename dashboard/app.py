"""Verity dashboard: watch what your AI is doing in production."""
import json

import streamlit as st

from verity.store import init_db, recent_traces

st.set_page_config(page_title="Verity dashboard", layout="wide")
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
