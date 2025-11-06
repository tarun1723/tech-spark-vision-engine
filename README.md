tech-spark-vision-engine
related to the cyber security domain

# RICE (Routable IP Collector and Evaluator) 🛡️

RICE is a Python command-line application that acts as a mini-threat intelligence system. It collects real-time security data from multiple public sources (APIs) for any IP address, standardizes the results, and calculates a clear **Risk Score**.

This project demonstrates skills in **Data Acquisition, Data Wrangling, and Feature Engineering** within a cybersecurity context.

---

## ✨ How It Works

1.  **Collects Data:** Fetches reports from **AbuseIPDB**, **VirusTotal**, and **IPinfo**.
2.  **Calculates Score:** Combines the reports to generate a **Severity Score** (0-100) and a **Confidence Score** (0-100%) for data reliability.
3.  **Enriches Data:** Automatically cleans and formats network data (like correctly identifying the **ASN**).
4.  **Reports:** Prints a clean, standardized threat analysis report directly to your terminal.

---

## 🚀 Quick Start Guide

You only need **two files** in your project folder to run this: `rice_main.py` and `.env`.

### 1. Setup

First, install the necessary Python libraries:

```bash
pip install requests python-dotenv# tech-spark-vision-engine
related to the cyber security domain



# .env file content
# Replace these with your actual keys from each service.

ABUSEIPDB_API_KEY="YOUR_ABUSEIPDB_V2_KEY"
VT_API_KEY="YOUR_VIRUSTOTAL_V3_KEY"
IPINFO_TOKEN="YOUR_IPINFO_ACCESS_TOKEN"

# Optional: Set to True to print raw JSON data for debugging
RICE_DEBUG="False"



# Example: Checking a standard, benign IP
python rice_main.py 8.8.8.8

example output
======================================================================
🕵️  THREAT INTELLIGENCE REPORT FOR: 8.8.8.8
======================================================================

**SUMMARY:** LOW SEVERITY. The IP appears benign or has minimal recent reports. (Confidence: 100%)
------------------------------
**Reputation:** Benign
**Severity Score:** 0/100
**Confidence:** 100%

**🌐 GEOLOCATION & NETWORK**
  Country/Region: US / California
  City:           Mountain View
  Organization:   AS15169 Google LLC
  ASN:            AS15169

======================================================================
