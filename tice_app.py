import argparse
import json
import sys
import os
import re

# --- Fix for Import Error: Explicitly add the current directory to Python Path ---
# This ensures that Python can find the local tice_api_collector.py file.
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
# --------------------------------------------------------------------------------

# Import the necessary functions from the collector script
try:
    # Now this import should reliably find the functions
    from tice_api_collector import get_raw_threat_data, process_raw_data
except ImportError as e:
    # Changed error message to be more specific to the issue
    print(f"❌ Error: Failed to import functions from 'tice_api_collector.py'.")
    print(f"Details: {e}")
    print("Please ensure the file is present and the function names are correct.")
    sys.exit(1)


def is_valid_ip(ip_address: str) -> bool:
    """Simple check for basic IPv4 format validity."""
    # This is a basic regex for IPv4 address validation
    ipv4_regex = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    if re.match(ipv4_regex, ip_address):
        # Additional check to ensure octets are 0-255
        try:
            return all(0 <= int(octet) <= 255 for octet in ip_address.split('.'))
        except ValueError:
            return False
    return False


def display_report(report: dict):
    """Formats and prints the unified threat intelligence report."""
    print("\n" + "=" * 70)
    print(f"🕵️  THREAT INTELLIGENCE REPORT FOR: {report.get('ip_address', 'N/A')}")
    print("=" * 70)

    # --- Summary and Scores ---
    print(f"\n**SUMMARY:** {report.get('summary')}")
    print("-" * 30)
    print(f"**Reputation:** {report.get('reputation')}")
    print(f"**Severity Score:** {report.get('severity_score'):>3}/100")
    print(f"**Confidence:** {report.get('confidence_score') * 100:.0f}%")

    # --- Geolocation ---
    geo = report.get('geolocation', {})
    if geo:
        print("\n**🌐 GEOLOCATION & NETWORK**")
        print(f"  Country/Region: {geo.get('country', 'N/A')} / {geo.get('region', 'N/A')}")
        print(f"  City:           {geo.get('city', 'N/A')}")
        print(f"  Organization:   {geo.get('org', 'N/A')}")
        print(f"  ASN:            {geo.get('asn', 'N/A')}")

    # --- Categories ---
    categories = report.get('categories', [])
    if categories:
        print("\n**🚨 THREAT CATEGORIES**")
        for cat in sorted(set(categories)):
            print(f"  - {cat}")

    # --- Related Data ---
    domains = report.get('related_domains', [])
    if domains:
        print("\n**🔗 RELATED DATA**")
        for dom in domains:
            print(f"  - {dom}")

    # --- Raw Data (Optional) ---
    if os.environ.get("RICE_DEBUG") == "True":
        print("\n" + "=" * 70)
        print("🔍 RAW API RESULTS (DEBUG MODE)")
        print(json.dumps(report.get('raw_api_results', {}), indent=2))

    print("\n" + "=" * 70)


def main():
    """Main function to run the IP analysis CLI."""
    parser = argparse.ArgumentParser(
        description="RICE Threat Intelligence CLI: Collects, processes, and scores threat intel for an IP address."
    )
    parser.add_argument(
        "ip_address",
        type=str,
        help="The IPv4 address to check (e.g., 8.8.8.8)."
    )
    args = parser.parse_args()
    ip_address = args.ip_address

    # 1. Validation
    if not is_valid_ip(ip_address):
        print(f"❌ Error: '{ip_address}' is not a valid IPv4 address format.")
        sys.exit(1)

    print(f"Collecting threat intelligence data for {ip_address}...")

    # 2. Collection (Uses tice_api_collector.get_raw_threat_data)
    # API keys are expected to be set as environment variables (ABUSEIPDB_API_KEY, VT_API_KEY, IPINFO_TOKEN)
    try:
        raw_results = get_raw_threat_data(ip_address)
    except Exception as e:
        print(f"Critical error during API collection: {e}")
        sys.exit(1)

    # Check if all keys were missing, which would prevent any useful analysis
    if all(r.get('error', '').startswith('Missing') for r in raw_results.values()):
        print("🚨 WARNING: All API keys are missing or invalid.")
        print("Please set ABUSEIPDB_API_KEY, VT_API_KEY, and IPINFO_TOKEN environment variables to run live analysis.")
        print("--- Proceeding with processing to show key errors in raw results. ---")

    # 3. Processing (Uses tice_api_collector.process_raw_data, which contains the logic from tice_processor)
    try:
        final_report = process_raw_data(ip_address, raw_results)
    except Exception as e:
        print(f"Critical error during data processing/scoring: {e}")
        # Display the raw data if processing fails for debugging
        print("\n--- Raw Data Before Processing Failure ---")
        print(json.dumps(raw_results, indent=2))
        sys.exit(1)

    # 4. Display
    display_report(final_report)


if __name__ == "__main__":
    main()