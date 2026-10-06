import re, json, socket, ssl, ipaddress
from datetime import datetime
from urllib.parse import urlparse, urljoin
from pathlib import Path

import requests
import streamlit as st
from bs4 import BeautifulSoup

from analyzer import analyze_url, analyze_text, ollama_explain

st.set_page_config(page_title="PhishGuard AI", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# ---------- Styling ----------
st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background: #07111f; color: #e8eef7; }
[data-testid="stSidebar"] { background: #0b1728; border-right: 1px solid #1e314a; }
.block-container { padding-top: 2rem; max-width: 1400px; }
.phish-title { font-size: 2.5rem; font-weight: 800; margin-bottom: .25rem; }
.phish-sub { color: #91a4bb; margin-bottom: 1.5rem; }
.card { background: #0d1b2e; border: 1px solid #203650; border-radius: 16px; padding: 22px; margin-bottom: 16px; }
.risk-safe { border-left: 6px solid #28c76f; }
.risk-suspicious { border-left: 6px solid #ffb020; }
.risk-danger { border-left: 6px solid #ff4d6d; }
.metric { background: #101f33; border: 1px solid #223b58; border-radius: 14px; padding: 16px; text-align: center; }
.metric-value { font-size: 2rem; font-weight: 800; }
.small { color: #91a4bb; font-size: .9rem; }
.badge { display:inline-block; padding:5px 10px; border-radius:999px; font-weight:700; font-size:.82rem; }
</style>
""", unsafe_allow_html=True)

if "history" not in st.session_state:
    st.session_state.history = []
if "last_result" not in st.session_state:
    st.session_state.last_result = None

with st.sidebar:
    st.markdown("# 🛡️ PhishGuard")
    st.caption("AI-powered phishing website & message analyzer")
    page = st.radio("Navigation", ["🔍 Scanner", "📊 Threat Report", "📜 Scan History", "⚙️ Settings"], label_visibility="collapsed")
    st.divider()
    st.markdown("**Local AI**")
    model = st.text_input("Ollama model", value="llama3.2")
    ollama_url = st.text_input("Ollama URL", value="http://127.0.0.1:11434")
    st.caption("Ollama is used locally for explanations. The rule-based scanner works even if Ollama is unavailable.")

if page == "🔍 Scanner":
    st.markdown('<div class="phish-title">Security Threat Scanner</div>', unsafe_allow_html=True)
    st.markdown('<div class="phish-sub">Analyze websites, URLs, emails, SMS and chat messages for phishing indicators.</div>', unsafe_allow_html=True)

    analyzer_type = st.segmented_control("Analyzer", ["🌐 Website / URL", "✉️ Email / Text", "💬 SMS / Chat"], default="🌐 Website / URL")

    if analyzer_type == "🌐 Website / URL":
        url = st.text_input("Destination URL", placeholder="https://example.com/login")
        st.caption("Checks URL structure, domain reputation heuristics, redirects, DNS, TLS, page forms and suspicious content. Do not enter passwords or private data.")
        scan = st.button("🚀 Trigger Security Scan", type="primary", use_container_width=True)
        if scan:
            if not url.strip():
                st.error("Please enter a URL.")
            else:
                with st.spinner("Running safe URL checks…"):
                    result = analyze_url(url.strip())
                    result["ai_explanation"] = ollama_explain(result, model, ollama_url)
                    result["timestamp"] = datetime.now().isoformat(timespec="seconds")
                    st.session_state.last_result = result
                    st.session_state.history.insert(0, result)

    elif analyzer_type == "✉️ Email / Text":
        text = st.text_area("Paste email headers + body", height=300, placeholder="From: security@example.com\nSubject: Urgent action required...\n\nYour account will be suspended...")
        scan = st.button("🚀 Analyze Email", type="primary", use_container_width=True)
        if scan:
            if not text.strip(): st.error("Paste the email content first.")
            else:
                with st.spinner("Analyzing email indicators…"):
                    result = analyze_text(text, "email")
                    result["ai_explanation"] = ollama_explain(result, model, ollama_url)
                    result["timestamp"] = datetime.now().isoformat(timespec="seconds")
                    st.session_state.last_result = result
                    st.session_state.history.insert(0, result)

    else:
        text = st.text_area("Paste SMS / chat message", height=220, placeholder="Your bank account is locked. Verify now: https://...")
        scan = st.button("🚀 Analyze Message", type="primary", use_container_width=True)
        if scan:
            if not text.strip(): st.error("Paste the message first.")
            else:
                with st.spinner("Analyzing message and links…"):
                    result = analyze_text(text, "message")
                    result["ai_explanation"] = ollama_explain(result, model, ollama_url)
                    result["timestamp"] = datetime.now().isoformat(timespec="seconds")
                    st.session_state.last_result = result
                    st.session_state.history.insert(0, result)

    if st.session_state.last_result:
        st.divider()
        st.subheader("Latest Result")
        r = st.session_state.last_result
        cols = st.columns(4)
        cols[0].metric("Classification", r["classification"])
        cols[1].metric("Risk Score", f'{r["risk_score"]:.1f}%')
        cols[2].metric("Risk Level", r["risk_level"])
        cols[3].metric("Confidence", r["confidence"])
        st.progress(min(max(r["risk_score"] / 100, 0), 1))
        if r["classification"] == "SAFE": st.success(r["recommendation"])
        elif r["classification"] == "SUSPICIOUS": st.warning(r["recommendation"])
        else: st.error(r["recommendation"])

elif page == "📊 Threat Report":
    st.markdown('<div class="phish-title">Threat Report</div>', unsafe_allow_html=True)
    r = st.session_state.last_result
    if not r:
        st.info("Run a scan to generate a threat report.")
    else:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Classification", r["classification"])
        c2.metric("Risk", f'{r["risk_score"]:.1f}%')
        c3.metric("Level", r["risk_level"])
        c4.metric("Confidence", r["confidence"])
        st.progress(min(max(r["risk_score"] / 100, 0), 1))
        st.markdown("### 🔎 Evidence")
        for item in r.get("evidence", []):
            st.write(item)
        st.markdown("### 🛡️ Recommendation")
        st.info(r["recommendation"])
        st.markdown("### 🧠 Ollama AI Explanation")
        st.markdown(r.get("ai_explanation", "No AI explanation available."))
        with st.expander("Technical details"):
            st.json(r.get("details", {}))

elif page == "📜 Scan History":
    st.markdown('<div class="phish-title">Scan History</div>', unsafe_allow_html=True)
    if not st.session_state.history:
        st.info("No scans yet.")
    else:
        for i, r in enumerate(st.session_state.history):
            label = f'{r["classification"]} · {r["risk_score"]:.1f}% · {r.get("target", "text")}'
            with st.expander(label):
                st.write("Time:", r.get("timestamp", ""))
                st.write("Risk level:", r["risk_level"])
                for e in r.get("evidence", []): st.write(e)
    if st.session_state.history and st.button("Clear local history"):
        st.session_state.history = []
        st.session_state.last_result = None
        st.rerun()

else:
    st.markdown('<div class="phish-title">Settings</div>', unsafe_allow_html=True)
    st.markdown("### Ollama")
    st.write(f"Endpoint: `{ollama_url}`")
    st.write(f"Model: `{model}`")
    st.code("ollama pull llama3.2\nollama serve", language="bash")
    st.info("The app does not send scanned content to a cloud AI service. Ollama runs on your computer. Network requests are only used when you choose to analyze a public URL.")
    st.markdown("### Detection notes")
    st.write("This is a defensive screening tool, not a guarantee that a website is safe. Never submit passwords, OTPs, card numbers or other secrets to a suspicious website.")
