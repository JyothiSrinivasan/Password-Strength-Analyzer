import math
import re
from pathlib import Path

import streamlit as st

st.set_page_config(page_title="Password Strength Analyzer", page_icon="🔐")

COMMON_FILE = Path(__file__).with_name("common_passwords.txt")


def pool_estimate(password):
    pool = 0
    pool += 26 if re.search(r"[a-z]", password) else 0
    pool += 26 if re.search(r"[A-Z]", password) else 0
    pool += 10 if re.search(r"[0-9]", password) else 0
    pool += 32 if re.search(r"[^A-Za-z0-9]", password) else 0
    return round(len(password) * math.log2(pool), 1) if pool else 0


def check_common(password):
    if not COMMON_FILE.exists():
        return None

    with COMMON_FILE.open(encoding="utf-8") as file:
        return any(
            password.casefold() == line.strip().casefold()
            for line in file
        )


def analyze(password):
    common = check_common(password)
    length = len(password)

    # A visual feedback score, not a measure of actual cracking time.
    score = min(length * 4, 60)
    score += 10 if re.search(r"[a-z]", password) else 0
    score += 10 if re.search(r"[A-Z]", password) else 0
    score += 10 if re.search(r"[0-9]", password) else 0
    score += 10 if re.search(r"[^A-Za-z0-9]", password) else 0

    patterns = []
    if re.search(r"(.)\1{2,}", password):
        patterns.append("Repeated characters")
        score -= 15
    if re.search(r"(?i)(password|admin|welcome|qwerty|1234)", password):
        patterns.append("Predictable word or sequence")
        score -= 35
    if common is True:
        score = min(score, 10)

    score = max(0, min(score, 100))
    label = "Weak" if score < 40 else "Moderate" if score < 75 else "Strong"
    return score, label, common, patterns


st.title("🔐 Password Strength Analyzer")
st.caption("Check length, common passwords, and predictable patterns.")

password = st.text_input(
    "Enter a password to analyze",
    type="password",
    placeholder="Type a sample password",
)

if password:
    score, label, common, patterns = analyze(password)
    color = "#ef4444" if score < 40 else "#f59e0b" if score < 75 else "#22c55e"

    st.subheader("Strength Score")
    st.markdown(
        f"<h2 style='color:{color}; margin:0'>{score}/100 · {label}</h2>",
        unsafe_allow_html=True,
    )
    st.progress(score)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🛡️ Estimated Entropy", f"{pool_estimate(password)} bits")
        if common is True:
            st.caption("⚠️ Not meaningful for a common password")
    col2.metric("📋 Length", len(password))
    col3.metric(
        "＃ Common Password",
        "Not found" if common is False else
        "Found" if common is True else "List missing",
    )
    col4.metric("✅ Strength", label)

    if patterns:
        st.warning("Patterns noticed: " + ", ".join(patterns))
    elif common is not None:
        st.success("No simple patterns detected.")

    st.caption(
        "The bit estimate assumes random character selection. "
        "The score is feedback for this demo, not a security guarantee."
    )
else:
    st.info("Enter a sample password to see the analysis.")

if not COMMON_FILE.exists():
    st.caption(
        "Add common_passwords.txt beside app.py to enable the common-password check."
    )