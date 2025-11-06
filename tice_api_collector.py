# --- tice_api_collector.py ---

from typing import Dict, Any, Optional
import json
import os
import time
import re  # <-- NECESSARY FOR ASN EXTRACTION

try:
    import requests  # ensure requests is installed: pip install requests
except Exception:  # pragma: no cover
    requests = None

# ----------------------------------------------
# 🚨 ADDED TO LOAD API KEYS FROM .env FILE
# ----------------------------------------------
from dotenv import load_dotenv

# This function searches for a .env file and loads the key/value pairs
# into the environment variables (os.environ).
load_dotenv()
# ----------------------------------------------


# --- 1. Define Unified Output Schema ---
UNIFIED_SCHEMA = {
    "ip_address": "",
    "reputation": "Unknown",  # Malicious, Benign, or Unknown
    "confidence_score": 0.0,  # 0.0 to 1.0
    "severity_score": 0,  # 0 to 100
    "categories": [],  # List of consolidated threat types
    "geolocation": {},  # Consolidated geo/ASN data
    "related_domains": [],  # Consolidated domains/URLs linked to the IP
    "summary": "No conclusive threat data found."
}

# The __all__ line is placed here, after UNIFIED_SCHEMA is defined.
__all__ = ["get_raw_threat_data", "process_raw_data", "UNIFIED_SCHEMA"]


# -----------------------------
# 0. Raw Data Collector
# -----------------------------
def _safe_get(url: str, headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, Any]] = None,
              timeout: float = 8.0) -> Dict[str, Any]:
    """HTTP GET wrapper that returns {'error': '...'} on failure."""
    if requests is None:
        return {"error": "requests library not available"}
    try:
        r = requests.get(url, headers=headers or {}, params=params or {}, timeout=timeout)
        if r.status_code >= 400:
            try:
                body = r.json()
            except Exception:
                body = r.text
            return {"error": f"HTTP {r.status_code}", "details": body}
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def get_raw_threat_data(
        ip_address: str,
        *,
        max_age_days: int = 90,
        timeout: float = 8.0
) -> Dict[str, Any]:
    """
    Fetch raw threat intel from AbuseIPDB, VirusTotal, and IPinfo for a given IP.
    API keys are read from environment variables (loaded from .env).
    """
    abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
    virustotal_key = os.getenv("VT_API_KEY")
    ipinfo_token = os.getenv("IPINFO_TOKEN")

    results: Dict[str, Any] = {}

    # --- AbuseIPDB ---
    if abuseipdb_key:
        abuse_headers = {
            "Key": abuseipdb_key,
            "Accept": "application/json",
        }
        abuse_params = {"ipAddress": ip_address, "maxAgeInDays": max_age_days}
        abuse = _safe_get("https://api.abuseipdb.com/api/v2/check", headers=abuse_headers, params=abuse_params,
                          timeout=timeout)
        if not abuse.get("error"):
            abuse = abuse.get("data", abuse)
        results["AbuseIPDB"] = abuse
        time.sleep(0.1)
    else:
        results["AbuseIPDB"] = {"error": "Missing ABUSEIPDB_API_KEY"}

    # --- VirusTotal (v3) ---
    if virustotal_key:
        vt_headers = {"x-apikey": virustotal_key}
        vt = _safe_get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}", headers=vt_headers,
                       timeout=timeout)
        if not vt.get("error"):
            vt = vt.get("data", vt)
            if isinstance(vt, dict) and "attributes" not in vt and "attributes" in vt.get("data", {}):
                vt = vt["data"]
        results["VirusTotal"] = vt
        time.sleep(0.1)
    else:
        results["VirusTotal"] = {"error": "Missing VT_API_KEY"}

    # --- IPinfo ---
    if ipinfo_token:
        ipinfo = _safe_get(f"https://ipinfo.io/{ip_address}", params={"token": ipinfo_token}, timeout=timeout)
        results["IPinfo"] = ipinfo
    else:
        results["IPinfo"] = {"error": "Missing IPINFO_TOKEN"}

    return results


# -----------------------------
# 2. API Parsing Functions
# -----------------------------
def parse_abuseipdb(raw_data: Dict[str, Any], unified_data: Dict[str, Any]) -> None:
    """Parses AbuseIPDB data into the unified schema."""
    if raw_data.get('error'):
        return
    abuse_score = raw_data.get('abuseConfidenceScore', 0)
    if abuse_score >= 50:
        unified_data['reputation'] = 'Malicious'
    elif unified_data['reputation'] == 'Unknown' and abuse_score < 10 and raw_data.get('isWhitelisted') is True:
        unified_data['reputation'] = 'Benign'

    unified_data.setdefault('geolocation', {})
    unified_data['geolocation']['country'] = raw_data.get('countryCode')
    unified_data['geolocation']['asn'] = raw_data.get('asn')
    unified_data['geolocation']['hostnames'] = raw_data.get('hostnames', [])

    if raw_data.get('totalReports', 0) > 0:
        unified_data['categories'].append(f"AbuseIPDB Reports ({raw_data['totalReports']})")

    unified_data['__abuse_score'] = abuse_score


def parse_virustotal(raw_data: Dict[str, Any], unified_data: Dict[str, Any]) -> None:
    """Parses VirusTotal data into the unified schema."""
    if raw_data.get('error') or not raw_data:
        return
    analysis_stats = raw_data.get('attributes', {}).get('last_analysis_stats', {})
    malicious_count = analysis_stats.get('malicious', 0) + analysis_stats.get('suspicious', 0)
    if malicious_count > 0:
        unified_data['reputation'] = 'Malicious'
        unified_data['categories'].append(f"VirusTotal Malicious Hits ({malicious_count})")
    if raw_data.get('attributes', {}).get('last_https_certificate'):
        unified_data['related_domains'].append("Certificate details available in raw VT data.")
    unified_data['__vt_malicious_count'] = malicious_count


def parse_ipinfo(raw_data: Dict[str, Any], unified_data: Dict[str, Any]) -> None:
    """
    Parses IPinfo data for geolocation/ASN/org.
    Includes robust logic to extract ASN from the 'org' string if the 'asn'
    field is missing or None.
    """
    if raw_data.get('error'):
        return

    unified_data.setdefault('geolocation', {})

    # 1. Basic Field Extraction
    org_string = raw_data.get('org')

    unified_data['geolocation']['city'] = raw_data.get('city')
    unified_data['geolocation']['region'] = raw_data.get('region')
    unified_data['geolocation']['org'] = org_string
    unified_data['geolocation']['country'] = raw_data.get('country')

    # 2. Get ASN (Official or Extracted)
    # Start with the official field from the API.
    asn_value = raw_data.get('asn')

    # If the official 'asn' field is not present, attempt to extract it from 'org'.
    # We check if asn_value is None OR an empty string ("")
    if not asn_value and org_string:
        # Regex to find 'AS' followed by one or more digits at the start of the string
        asn_match = re.match(r'^(AS\d+)', org_string)

        if asn_match:
            asn_value = asn_match.group(1)

            # Set the final ASN value (either the official one, the extracted one, or None/initial)
    unified_data['geolocation']['asn'] = asn_value


# -----------------------------
# 3. Scoring Mechanism
# -----------------------------
def calculate_score(unified_data: Dict[str, Any], raw_results: Dict[str, Any]) -> None:
    """Calculates confidence and severity scores."""
    apis_attempted = len(raw_results)
    apis_successful = sum(1 for data in raw_results.values() if not data.get('error'))
    unified_data['confidence_score'] = round(apis_successful / apis_attempted, 2) if apis_attempted else 0.0

    severity = 0
    abuse_score = unified_data.pop('__abuse_score', 0)
    severity += int(abuse_score * 0.5)

    vt_count = unified_data.pop('__vt_malicious_count', 0)
    if vt_count > 0:
        severity += min(vt_count * 5, 30)

    if unified_data['reputation'] == 'Malicious':
        severity += 20

    unified_data['severity_score'] = min(severity, 100)


def generate_summary(unified_data: Dict[str, Any]) -> None:
    """Creates a concise human-readable conclusion."""
    severity = unified_data['severity_score']
    confidence = unified_data['confidence_score']
    categories = ", ".join(sorted(list(set(unified_data['categories']))))

    if severity >= 80:
        conclusion = "HIGH SEVERITY threat detected. The IP is highly likely malicious."
    elif severity >= 40:
        conclusion = "MEDIUM SEVERITY threat. Multiple indicators point to potential risk."
    else:
        conclusion = "LOW SEVERITY. The IP appears benign or has minimal recent reports."

    if categories:
        conclusion += f" Key threat categories identified: {categories}."
    conclusion += f" (Confidence: {confidence * 100:.0f}%)"
    unified_data['summary'] = conclusion


def process_raw_data(ip_address: str, raw_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main function to transform raw API results into a single unified report.
    This function is required for import into rice_app.py.
    """
    unified_data = UNIFIED_SCHEMA.copy()
    unified_data['ip_address'] = ip_address

    # 1. Apply Parsers (order matters)
    parse_ipinfo(raw_results.get('IPinfo', {}) or {}, unified_data)
    parse_abuseipdb(raw_results.get('AbuseIPDB', {}) or {}, unified_data)
    parse_virustotal(raw_results.get('VirusTotal', {}) or {}, unified_data)

    # 2. Calculate Scores
    calculate_score(unified_data, raw_results)

    # 3. Generate Summary
    generate_summary(unified_data)

    # Cleanup temp fields if any slipped through
    for key in list(unified_data.keys()):
        if key.startswith('__'):
            del unified_data[key]

    # Include raw data for context
    unified_data['raw_api_results'] = raw_results
    return unified_data