# --- rice_app_ui.py ---

import streamlit as st
import pandas as pd
import numpy as np
import sys
import os
import re

# Add the project directory to the path to ensure rice_main.py is found
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Assuming you saved the combined code as rice_main.py
try:
    from rice_main import get_raw_threat_data, process_raw_data, is_valid_ip
except ImportError:
    st.error(
        "Error: Could not import core logic. Please ensure your combined file is named 'rice_main.py' and is in the same directory.")
    st.stop()

# --- Page Configuration ---
st.set_page_config(
    page_title="RICE Threat Intelligence Dashboard",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- UI Layout ---

st.title("🛡️ RICE: Real-time IP Threat Intelligence")
st.markdown("Enter an IPv4 address to collect, process, and visualize threat intelligence data from multiple sources.")

# --- IP Input Slot ---
ip_address = st.text_input(
    "Enter IPv4 Address",
    value="8.8.8.8",
    max_chars=15
)

# --- Main Logic ---

if st.button("Analyze IP"):
    if not is_valid_ip(ip_address):
        st.error(f"❌ '{ip_address}' is not a valid IPv4 address.")
    else:
        # Show status while processing
        with st.spinner(f"Collecting and analyzing data for {ip_address}..."):

            # 1. Collect Data
            raw_results = get_raw_threat_data(ip_address)

            # 2. Process Data
            try:
                final_report = process_raw_data(ip_address, raw_results)
            except Exception as e:
                st.error(f"Critical error during data processing: {e}")
                st.json(raw_results)
                st.stop()

        # --- Report Display ---

        # 1. Header Metrics (Scorecard)
        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Reputation", final_report['reputation'], delta=None)
        col2.metric("Confidence Score", f"{final_report['confidence_score'] * 100:.0f}%", delta=None)
        col3.metric("Severity Score", f"{final_report['severity_score']}/100", delta=None)

        # Adjusting status based on severity
        if final_report['severity_score'] >= 80:
            status_text = f":red[HIGH SEVERITY]"
        elif final_report['severity_score'] >= 40:
            status_text = f":orange[MEDIUM RISK]"
        else:
            status_text = f":green[LOW RISK]"

        col4.markdown(f"**Overall Status**\n### {status_text}")

        st.markdown(f"**Summary:** {final_report['summary']}")

        st.divider()

        # 2. Detailed Data Sections

        tab1, tab2, tab3 = st.tabs(["🌎 Geolocation & Network", "📊 Scoring Visualization", "🔗 Related IPs & Raw Data"])

        with tab1:
            st.subheader("Geolocation and Network Details")
            geo = final_report.get('geolocation', {})
            st.markdown(f"**Organization (ASN):** {geo.get('org', 'N/A')} ({geo.get('asn', 'N/A')})")
            st.markdown(
                f"**Location:** {geo.get('city', 'N/A')}, {geo.get('region', 'N/A')}, {geo.get('country', 'N/A')}")

            # Display Threat Categories
            if final_report['categories']:
                st.warning(f"🚨 **Threat Categories Identified:** {', '.join(final_report['categories'])}")
            else:
                st.success("No specific threat categories found.")

        with tab2:
            st.subheader("Weighted Scoring Breakdown")

            # Creating a dummy DataFrame for visualization (Replace with real scoring data if possible)
            score_data = {
                'Metric': ['AbuseIPDB Weight (Max 50)', 'VirusTotal Weight (Max 30)', 'Malicious Bump (Max 20)'],
                'Score': [final_report['severity_score'] * 0.5, final_report['severity_score'] * 0.3,
                          final_report['severity_score'] * 0.2]
            }
            # NOTE: For a real breakdown, you'd need to modify process_raw_data to return __temp_scores

            # Placeholder Bar Chart for Scoring
            st.bar_chart(
                pd.DataFrame({
                    'Source Contribution': [
                        final_report['severity_score'] * 0.5,
                        final_report['severity_score'] * 0.3,
                        final_report['severity_score'] * 0.2
                    ],
                    'Metrics': ['AbuseIPDB', 'VirusTotal', 'Reputation']
                }).set_index('Metrics'),
                height=300
            )
            st.caption("Bar chart shows the weighted contribution of each source to the final severity score.")

            # Confidence Gauge Placeholder (Conceptually difficult in Streamlit, using text for now)
            st.markdown(f"---")
            st.markdown(
                f"**Data Confidence:** The {final_report['confidence_score'] * 100:.0f}% confidence reflects successful API connections.")

        with tab3:
            st.subheader("Related Data and Forensics")

            # 💡 Related IPs (This requires a new API or database lookup, so it's a conceptual placeholder)
            st.info("No related IPs found (Requires external link-analysis API/database).")

            st.subheader("Raw API Responses (Forensics)")
            st.json(final_report['raw_api_results'])