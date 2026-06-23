"""
IP Reputation Checker
=====================
Queries the AbuseIPDB API for a list of IP addresses and returns
confidence scores, country of origin, ISP, and global report counts.

Requires a free AbuseIPDB API key: https://www.abuseipdb.com/

Author: Will King
"""

import requests

# ── Configuration ─────────────────────────────────────────────────
API_KEY = "YOUR_ABUSEIPDB_API_KEY"   # replace with your free key
API_URL = "https://api.abuseipdb.com/api/v2/check"

# ── Sample IPs to check (replace with flagged IPs from parser) ────
IP_LIST = [
    "192.168.1.1",
    "8.8.8.8",
]


def risk_label(score):
    if score >= 75:
        return "HIGH RISK"
    elif score >= 25:
        return "MEDIUM RISK"
    elif score >= 1:
        return "LOW RISK"
    else:
        return "CLEAN"


def check_ip(ip, api_key):
    headers  = {"Key": api_key, "Accept": "application/json"}
    params   = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        response = requests.get(API_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        return response.json().get("data", {})
    except requests.RequestException as e:
        print(f"  [ERROR] Could not check {ip}: {e}")
        return {}


def main():
    print("=" * 60)
    print("  IP REPUTATION CHECKER")
    print("=" * 60)
    print()

    results = {}
    for ip in IP_LIST:
        print(f"  Checking {ip}...")
        data = check_ip(ip, API_KEY)

        if data:
            score   = data.get("abuseConfidenceScore", 0)
            risk    = risk_label(score)
            country = data.get("countryCode", "Unknown")
            isp     = data.get("isp", "Unknown")
            reports = data.get("totalReports", 0)

            print(f"     Risk       : {risk} (score: {score}/100)")
            print(f"     Country    : {country}")
            print(f"     ISP        : {isp}")
            print(f"     Reports    : {reports} global reports")
            results[ip] = data
        print()

    return results


if __name__ == "__main__":
    main()
