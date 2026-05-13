#!/usr/bin/env python3
"""
SupplyShield Web Interface — Streamlit Application
=====================================================
Public-facing web platform for scanning PyPI packages.
Anyone with a browser can use SupplyShield without installing anything.

Run locally:
  streamlit run app.py

Deploy free:
  - Streamlit Cloud: https://streamlit.io/cloud (connect GitHub repo)
  - Hugging Face Spaces: https://huggingface.co/spaces


"""

import streamlit as st
import json
import time
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src" / "cli"))

from supplyshield import (
    scan_package, ATTACK_TAXONOMY, load_model, load_top_packages,
)

# ============================================================================
# PAGE CONFIG
# ============================================================================

st.set_page_config(
    page_title="SupplyShield — PyPI Package Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================================
# CUSTOM CSS
# ============================================================================

st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #0F1B2D;
        margin-bottom: 0;
    }
    .sub-header {
        font-size: 1.1rem;
        color: #64748B;
        margin-top: -10px;
        margin-bottom: 30px;
    }
    .risk-clean { color: #00C48C; font-weight: 700; font-size: 1.5rem; }
    .risk-low { color: #00C48C; font-weight: 700; font-size: 1.5rem; }
    .risk-medium { color: #FF8C42; font-weight: 700; font-size: 1.5rem; }
    .risk-high { color: #FF4D4D; font-weight: 700; font-size: 1.5rem; }
    .risk-critical { color: #FF0000; font-weight: 700; font-size: 1.5rem; }
    .metric-card {
        background: #F8FAFC;
        border-radius: 8px;
        padding: 15px;
        border-left: 4px solid #2E75B6;
    }
    .stAlert { margin-top: 10px; }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# SIDEBAR
# ============================================================================

with st.sidebar:
    st.image("https://img.shields.io/badge/SupplyShield-v1.0-blue?style=for-the-badge", width=200)
    st.markdown("### About")
    st.markdown("""
    **SupplyShield** is an explainable multi-modal ML system
    for detecting malicious Python packages on PyPI.

    **Three-Tier Detection:**
    - 🔵 **Metadata Analysis** (21 features)
    - 🟢 **Static Code Analysis** (45 features)
    - 🟣 **Stylometric Consistency** (8 features)

    **Model:** XGBoost (F1 = 0.9993)
    """)

    st.markdown("---")
    st.markdown("### How It Works")
    st.markdown("""
    1. Enter a PyPI package name
    2. SupplyShield queries the PyPI API
    3. Downloads and analyzes source code
    4. Runs the trained ML classifier
    5. Provides explainable risk assessment
    """)

    st.markdown("---")
    st.markdown("""
    
    """)

# ============================================================================
# MAIN INTERFACE
# ============================================================================

st.markdown('<p class="main-header">🛡️ SupplyShield</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">Explainable Multi-Modal ML for Detecting Malicious PyPI Packages</p>', unsafe_allow_html=True)

# Input section
col1, col2, col3 = st.columns([4, 1, 1])
with col1:
    package_name = st.text_input(
        "Enter PyPI package name:",
        placeholder="e.g., requests, flask, numpy...",
        label_visibility="collapsed",
    )
with col2:
    version = st.text_input("Version (optional)", placeholder="latest", label_visibility="collapsed")
with col3:
    scan_button = st.button("🔍 Scan Package", type="primary", use_container_width=True)

# Quick examples
st.markdown("**Try these examples:** ", unsafe_allow_html=True)
example_cols = st.columns(6)
examples = ["requests", "flask", "numpy", "colorama", "requesra", "django"]
for i, pkg in enumerate(examples):
    with example_cols[i]:
        if st.button(pkg, key=f"ex_{pkg}", use_container_width=True):
            package_name = pkg
            scan_button = True

st.markdown("---")

# ============================================================================
# SCAN AND RESULTS
# ============================================================================

if scan_button and package_name:
    package_name = package_name.strip()
    ver = version.strip() if version and version.strip() else None

    with st.spinner(f"Scanning **{package_name}**... (querying PyPI, analyzing code)"):
        start_time = time.time()
        try:
            result = scan_package(package_name, ver)
        except Exception as e:
            st.error(f"Scan failed: {str(e)}")
            st.stop()
        scan_time = time.time() - start_time

    # ── Results Header ──
    risk = result["risk_level"]
    confidence = result["confidence"]

    risk_class = f"risk-{risk.lower()}"
    risk_emoji = {"CLEAN": "✅", "LOW": "✅", "MEDIUM": "⚠️", "HIGH": "🚨", "CRITICAL": "🚫"}.get(risk, "❓")

    st.markdown(f"## {risk_emoji} Scan Result: `{package_name}`")

    # Metric cards
    mcol1, mcol2, mcol3, mcol4 = st.columns(4)
    with mcol1:
        st.metric("Risk Level", risk)
    with mcol2:
        st.metric("Confidence", f"{confidence:.2%}")
    with mcol3:
        st.metric("Scan Time", f"{result['scan_time']:.2f}s")
    with mcol4:
        verdict = "MALICIOUS" if result["prediction"] == 1 else "BENIGN"
        st.metric("Verdict", verdict)

    # Modalities
    st.markdown("### Modalities Evaluated")
    mod_cols = st.columns(3)
    mods = result["modalities"]
    with mod_cols[0]:
        icon = "✅" if mods["metadata"] else "❌"
        st.info(f"{icon} **Metadata Analysis** (21 features)\n\nAlways available via PyPI API")
    with mod_cols[1]:
        icon = "✅" if mods["code"] else "⬜"
        status = "Source code analyzed" if mods["code"] else "Source unavailable"
        st.info(f"{icon} **Static Code Analysis** (45 features)\n\n{status}")
    with mod_cols[2]:
        icon = "✅" if mods["stylometric"] else "⬜"
        status = "Multi-file package analyzed" if mods["stylometric"] else "Single file or unavailable"
        st.info(f"{icon} **Stylometric Consistency** (8 features)\n\n{status}")

    # Attack Details (if malicious)
    if result["prediction"] == 1:
        st.markdown("### ⚠️ Attack Classification")

        av = result.get("attack_vector", "AV-000")
        av_info = ATTACK_TAXONOMY.get(av, {})

        acol1, acol2, acol3 = st.columns(3)
        with acol1:
            st.error(f"**Primary Attack Vector**\n\n{av} — {av_info.get('name', 'Unknown')}")
        with acol2:
            st.warning(f"**Severity**\n\n{av_info.get('severity', 'N/A')}")
        with acol3:
            st.info(f"**MITRE ATT&CK**\n\n{av_info.get('mitre', 'N/A')}")

        if result.get("secondary_vectors"):
            sec = ", ".join([f"{v} ({ATTACK_TAXONOMY[v]['name']})" for v in result["secondary_vectors"]])
            st.markdown(f"**Secondary Indicators:** {sec}")

        # SHAP Evidence
        if result.get("top_features"):
            st.markdown("### 🔍 SHAP Evidence (Top Contributing Features)")
            for feat in result["top_features"][:5]:
                desc = feat.get("description", feat["feature"])
                shap_val = feat["shap_value"]
                direction = "🔴 Suspicious" if shap_val > 0 else "🟢 Absent/low"
                st.markdown(f"- **{desc}**: {direction} (SHAP: `{shap_val:+.4f}`)")

        # Recommendation
        st.markdown("---")
        st.error("### 🚫 Recommendation: DO NOT INSTALL\n\nThis package exhibits indicators of malicious behavior. "
                 "Review the evidence above and verify the package source before installation.")

    else:
        # Clean package
        st.markdown("---")
        st.success("### ✅ Recommendation: Safe to Install\n\nNo indicators of malicious behavior detected across all evaluated modalities.")

        # Show SHAP for clean packages too (educational)
        if result.get("top_features"):
            with st.expander("Show feature analysis (educational)"):
                for feat in result["top_features"][:5]:
                    desc = feat.get("description", feat["feature"])
                    shap_val = feat["shap_value"]
                    direction = "→ pushes toward malicious" if shap_val > 0 else "→ pushes toward benign"
                    st.markdown(f"- **{desc}**: SHAP `{shap_val:+.4f}` {direction}")

    # Raw JSON (expandable)
    with st.expander("View raw scan data (JSON)"):
        raw = {
            "package": package_name,
            "version": ver,
            "risk_level": risk,
            "confidence": confidence,
            "prediction": "malicious" if result["prediction"] == 1 else "benign",
            "attack_vector": result.get("attack_vector", "AV-000"),
            "modalities": result["modalities"],
            "top_features": result.get("top_features", [])[:5],
            "scan_time": round(result["scan_time"], 3),
        }
        st.json(raw)

elif scan_button and not package_name:
    st.warning("Please enter a package name to scan.")

# ============================================================================
# FOOTER
# ============================================================================

st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #94A3B8; font-size: 12px;">
    SupplyShield v1.0 <br>
    Model: XGBoost (F1=0.9993) | Dataset: 18,542 packages | 74 features | 7 Ladisa taxonomy attack vectors
</div>
""", unsafe_allow_html=True)
