"""
Brute Force Log Parser
======================
Reads Linux authentication logs (auth.log) and uses regex to count
failed SSH login attempts per IP address. Flags IPs that hit the
threshold and cross-references against successful logins.

Author: Will King
"""

import re
from collections import defaultdict

# ── Configuration ─────────────────────────────────────────────────
LOG_FILE  = "/var/log/auth.log"   # path to your auth log
THRESHOLD = 5                      # failed attempts before flagging

# ── Regex patterns ─────────────────────────────────────────────────
FAIL_PATTERN    = re.compile(r"Failed password for (\S+) from (\S+)")
SUCCESS_PATTERN = re.compile(r"Accepted password for (\S+) from (\S+)")

def parse_log(filepath):
    failures  = defaultdict(list)   # ip -> [usernames]
    successes = defaultdict(list)   # ip -> [usernames]

    try:
        with open(filepath, "r") as f:
            for line in f:
                fail_match = FAIL_PATTERN.search(line)
                if fail_match:
                    user, ip = fail_match.groups()
                    failures[ip].append(user)

                succ_match = SUCCESS_PATTERN.search(line)
                if succ_match:
                    user, ip = succ_match.groups()
                    successes[ip].append(user)

    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {filepath}")
        return {}, {}

    return failures, successes


def find_brute_force(failures, threshold):
    return {ip: users for ip, users in failures.items()
            if len(users) >= threshold}


def main():
    print("=" * 60)
    print("  BRUTE FORCE LOG PARSER")
    print("=" * 60)

    failures, successes = parse_log(LOG_FILE)
    flagged  = find_brute_force(failures, THRESHOLD)

    if not flagged:
        print(f"\n  No IPs exceeded the threshold of {THRESHOLD} failures.\n")
        return flagged, successes

    print(f"\n  {len(flagged)} IP(s) flagged (threshold: {THRESHOLD} attempts)\n")

    for ip, users in sorted(flagged.items(), key=lambda x: -len(x[1])):
        print(f"  IP: {ip}")
        print(f"     Failed attempts : {len(users)}")
        print(f"     Targeted users  : {', '.join(set(users))}")

        if ip in successes:
            print(f"     *** SUCCESSFUL LOGIN DETECTED — ESCALATE ***")
        print()

    return flagged, successes


if __name__ == "__main__":
    main()
