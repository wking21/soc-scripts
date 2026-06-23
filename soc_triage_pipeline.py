"""
Unified SOC Triage Pipeline
============================
Combines the brute force log parser, IP reputation checker, and
file integrity monitor into a single correlated triage workflow.

Run this script to get a full security picture in one pass:
  - Flagged IPs from auth log analysis
  - Reputation scores for each flagged IP
  - File system integrity check

Author: Will King
"""

import re
import os
import sys
import json
import hashlib
import requests
from collections import defaultdict

# ══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════

LOG_FILE      = "/var/log/auth.log"
THRESHOLD     = 5
API_KEY       = "YOUR_ABUSEIPDB_API_KEY"   # replace with your key
API_URL       = "https://api.abuseipdb.com/api/v2/check"
WATCH_DIR     = "/etc"
BASELINE_FILE = "fim_baseline.json"

# ══════════════════════════════════════════════════════════════════
# MODULE 1 — BRUTE FORCE LOG PARSER
# ══════════════════════════════════════════════════════════════════

FAIL_PATTERN    = re.compile(r"Failed password for (\S+) from (\S+)")
SUCCESS_PATTERN = re.compile(r"Accepted password for (\S+) from (\S+)")


def parse_log(filepath):
    failures  = defaultdict(list)
    successes = defaultdict(list)
    try:
        with open(filepath, "r") as f:
            for line in f:
                m = FAIL_PATTERN.search(line)
                if m:
                    failures[m.group(2)].append(m.group(1))
                m = SUCCESS_PATTERN.search(line)
                if m:
                    successes[m.group(2)].append(m.group(1))
    except FileNotFoundError:
        print(f"  [WARN] Log not found: {filepath} — skipping brute force check.")
    return failures, successes


def find_brute_force(failures, threshold):
    return {ip: users for ip, users in failures.items()
            if len(users) >= threshold}


# ══════════════════════════════════════════════════════════════════
# MODULE 2 — IP REPUTATION CHECKER
# ══════════════════════════════════════════════════════════════════

def risk_label(score):
    if score >= 75:   return "HIGH RISK"
    elif score >= 25: return "MEDIUM RISK"
    elif score >= 1:  return "LOW RISK"
    else:             return "CLEAN"


def check_ip(ip, api_key):
    headers = {"Key": api_key, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get(API_URL, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        return r.json().get("data", {})
    except requests.RequestException:
        return {"abuseConfidenceScore": 0, "isp": "Unknown",
                "countryCode": "??", "totalReports": 0}


# ══════════════════════════════════════════════════════════════════
# MODULE 3 — FILE INTEGRITY MONITOR
# ══════════════════════════════════════════════════════════════════

def hash_file(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError):
        return None


def build_snapshot(directory):
    snapshot = {}
    for root, _, files in os.walk(directory):
        for filename in files:
            fp = os.path.join(root, filename)
            h  = hash_file(fp)
            if h:
                snapshot[fp] = h
    return snapshot


def load_baseline(baseline_file):
    if not os.path.exists(baseline_file):
        return None
    with open(baseline_file, "r") as f:
        return json.load(f)


def compare_snapshots(baseline, current):
    b, c = set(baseline), set(current)
    return {
        "added":    list(c - b),
        "removed":  list(b - c),
        "modified": [f for f in b & c if baseline[f] != current[f]]
    }


# ══════════════════════════════════════════════════════════════════
# MAIN PIPELINE
# ══════════════════════════════════════════════════════════════════

def main():
    print()
    print("=" * 62)
    print("   SOC TRIAGE PIPELINE")
    print("=" * 62)

    # ── Step 1: Parse logs ────────────────────────────────────────
    print("\n  [1/3] Parsing authentication logs...")
    failures, successes = parse_log(LOG_FILE)
    flagged_ips = find_brute_force(failures, THRESHOLD)
    print(f"        {len(flagged_ips)} IP(s) flagged (threshold: {THRESHOLD})")

    # ── Step 2: Enrich with reputation data ───────────────────────
    print("\n  [2/3] Checking IP reputation...")
    enriched = {}
    if flagged_ips:
        for ip in flagged_ips:
            enriched[ip] = check_ip(ip, API_KEY)
            score = enriched[ip].get("abuseConfidenceScore", 0)
            print(f"        {ip} — {risk_label(score)} ({score}/100)")
    else:
        print("        No IPs to enrich.")

    # ── Step 3: File integrity check ──────────────────────────────
    print("\n  [3/3] Running file integrity check...")
    baseline = load_baseline(BASELINE_FILE)

    if baseline is None:
        print("        No baseline found — run file_integrity_monitor.py --baseline first.")
        total_changes = 0
        fim_results = None
    else:
        current = build_snapshot(WATCH_DIR)
        fim_results = compare_snapshots(baseline, current)
        total_changes = sum(len(v) for v in fim_results.values())
        print(f"        {total_changes} change(s) detected.")

    # ── Final report ──────────────────────────────────────────────
    print()
    print("=" * 62)
    print("   TRIAGE SUMMARY")
    print("=" * 62)

    print(f"\n  BRUTE FORCE ALERTS  ({len(flagged_ips)} IPs flagged)\n")
    if not flagged_ips:
        print("  No IPs met the threshold.")
    else:
        for ip, users in sorted(flagged_ips.items(), key=lambda x: -len(x[1])):
            rep   = enriched.get(ip, {})
            score = rep.get("abuseConfidenceScore", 0)
            risk  = risk_label(score)

            if score >= 75:   icon = "[HIGH]  "
            elif score >= 25: icon = "[MED]   "
            else:             icon = "[LOW]   "

            print(f"  {icon}{ip}")
            print(f"     Attempts   : {len(users)}")
            print(f"     Users hit  : {', '.join(set(users))}")
            print(f"     Reputation : {risk} (score: {score}/100)")
            print(f"     ISP        : {rep.get('isp', 'Unknown')}")
            print(f"     Country    : {rep.get('countryCode', '??')}")
            print(f"     Reports    : {rep.get('totalReports', 0)} global")

            if ip in successes:
                print(f"     *** SUCCESSFUL LOGIN DETECTED — ESCALATE IMMEDIATELY ***")
            print()

    print(f"  FILE INTEGRITY ALERTS  ({total_changes} change(s))\n")
    if fim_results is None:
        print("  Skipped — no baseline.")
    elif total_changes == 0:
        print("  No changes detected.")
    else:
        for f in fim_results["added"]:
            print(f"  [NEW]      {f}")
        for f in fim_results["removed"]:
            print(f"  [DELETED]  {f}")
        for f in fim_results["modified"]:
            print(f"  [MODIFIED] {f}")

    print()
    print("=" * 62)
    print("  Pipeline complete.")
    print("=" * 62)
    print()


if __name__ == "__main__":
    main()
