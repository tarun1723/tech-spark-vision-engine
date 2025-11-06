# tice_processor.py

from typing import Dict, Any

# --- Unified Output Schema (final standardized report shape) ---
UNIFIED_SCHEMA = {
    "ip_address": "",
    "reputation": "Unknown",      # Malicious, Benign, or Unknown
    "confidence_score": 0.0,      # 0.0 to 1.0 (proportion of successful API calls)
    "severity_score": 0,          # 0 to 100 (weighted by signals)
    "categories": [],             # Consolidated threat categories/notes
    "geolocation": {},            # Consolidated geo/ASN details
    "related_domains": [],        # Related domains/URLs if present
    "summary": "No conclusive threat data found."
}

# --- Parsers ---

def parse_abuseipdb(raw_data: Dict[str, Any], unified_data: Dict[str, Any]) -> None:
    """Parses AbuseIPDB data into the unified schema."""
    if raw_data.get('error'):
        return

    abuse_score = raw_data.get('abuseConfidenceScore', 0)

    # Reputation signal
    if abuse_score >= 50:
        unified_data['reputation'] = 'Malicious'
    elif unified_data['reputation'] == 'Unknown' and abuse_score < 10 and raw_data.get('isWhitelisted') is True:
        unified_data['reputation'] = 'Benign'

    # Geo/ASN/Hostnames
    unified_data.setdefault('geolocation', {})
    unified_data['geolocation']['country'] = raw_data.get('countryCode')
    unified_data['geolocation']['asn'] = raw_data.get('asn')
    unified_data['geolocation']['hostnames'] = raw_data.get('hostnames', [])

    # Category note (count of reports)
    if raw_data.get('totalReports', 0) > 0:
        unified_data['categories'].append(f"AbuseIPDB Reports ({raw_data['totalReports']})")

    # Temporary scoring aid
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

    # Temporary scoring aid
    unified_data['__vt_malicious_count'] = malicious_count


def parse_ipinfo(raw_data: Dict[str, Any], unified_data: Dict[str, Any]) -> None:
    """Parses IPinfo data for geolocation/ASN/org."""
    if raw_data.get('error'):
        return

    unified_data.setdefault('geolocation', {})
    unified_data['geolocation']['city'] = raw_data.get('city')
    unified_data['geolocation']['region'] = raw_data.get('region')
    unified_data['geolocation']['org'] = raw_data.get('org')
    unified_data['geolocation']['country'] = raw_data.get('country')
    unified_data['geolocation']['asn'] = raw_data.get('asn')


# --- Scoring, Summary ---

def calculate_score(unified_data: Dict[str, Any], raw_results: Dict[str, Any]) -> None:
    """Calculates confidence and severity scores."""
    # Confidence = fraction of APIs that returned without error
    apis_attempted = len(raw_results)
    apis_successful = sum(1 for data in raw_results.values() if not data.get('error'))
    unified_data['confidence_score'] = round(apis_successful / apis_attempted, 2) if apis_attempted else 0.0

    # Severity (0-100)
    severity = 0

    # AbuseIPDB weight: up to 50
    abuse_score = unified_data.pop('__abuse_score', 0)
    severity += int(abuse_score * 0.5)

    # VT detections weight: 5 per detection, capped at 30
    vt_count = unified_data.pop('__vt_malicious_count', 0)
    if vt_count > 0:
        severity += min(vt_count * 5, 30)

    # Reputation bump: +20 if marked malicious
    if unified_data['reputation'] == 'Malicious':
        severity += 20

    unified_data['severity_score'] = min(severity, 100)


def generate_summary(unified_data: Dict[str, Any]) -> None:
    """Creates a concise human-readable conclusion."""
    severity = unified_data['severity_score']
    confidence = unified_data['confidence_score']
    categories_str = ", ".join(sorted(set(unified_data['categories'])))

    if severity >= 80:
        conclusion = "HIGH SEVERITY threat detected. The IP is highly likely malicious."
    elif severity >= 40:
        conclusion = "MEDIUM SEVERITY threat. Multiple indicators point to potential risk."
    else:
        conclusion = "LOW SEVERITY. The IP appears benign or has minimal recent reports."

    if categories_str:
        conclusion += f" Key threat categories identified: {categories_str}."

    conclusion += f" (Confidence: {confidence * 100:.0f}%)"
    unified_data['summary'] = conclusion


# --- Public API ---

def process_raw_data(ip_address: str, raw_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main function to transform raw API results into a single unified report.
    Expected raw_results keys: 'AbuseIPDB', 'VirusTotal', 'IPinfo'
    """
    unified_data = UNIFIED_SCHEMA.copy()
    unified_data['ip_address'] = ip_address

    # 1) Parse (order matters for reputation overrides)
    parse_ipinfo(raw_results.get('IPinfo', {}) or {}, unified_data)
    parse_abuseipdb(raw_results.get('AbuseIPDB', {}) or {}, unified_data)
    parse_virustotal(raw_results.get('VirusTotal', {}) or {}, unified_data)

    # 2) Score
    calculate_score(unified_data, raw_results)

    # 3) Summarize
    generate_summary(unified_data)

    # Cleanup any temp fields
    for key in list(unified_data.keys()):
        if key.startswith('__'):
            del unified_data[key]

    # Include raw for forensics
    unified_data['raw_api_results'] = raw_results
    return unified_data


__all__ = ["process_raw_data"]
