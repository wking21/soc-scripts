"""
File Integrity Monitor
======================
Monitors a directory for file changes using SHA-256 hashing.
Run with --baseline to create an initial snapshot.
Run without flags to compare current state against the baseline.

Author: Will King
"""

import os
import sys
import json
import hashlib

# ── Configuration ─────────────────────────────────────────────────
WATCH_DIR    = "/etc"               # directory to monitor
BASELINE_FILE = "fim_baseline.json" # where baseline is saved


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
            filepath = os.path.join(root, filename)
            file_hash = hash_file(filepath)
            if file_hash:
                snapshot[filepath] = file_hash
    return snapshot


def save_baseline(snapshot, baseline_file):
    with open(baseline_file, "w") as f:
        json.dump(snapshot, f, indent=2)
    print(f"  Baseline saved: {len(snapshot)} files hashed.")
    print(f"  Stored in: {baseline_file}")


def load_baseline(baseline_file):
    if not os.path.exists(baseline_file):
        return None
    with open(baseline_file, "r") as f:
        return json.load(f)


def compare_snapshots(baseline, current):
    baseline_set = set(baseline.keys())
    current_set  = set(current.keys())

    added    = list(current_set - baseline_set)
    removed  = list(baseline_set - current_set)
    modified = [
        f for f in baseline_set & current_set
        if baseline[f] != current[f]
    ]

    return {"added": added, "removed": removed, "modified": modified}


def main():
    print("=" * 60)
    print("  FILE INTEGRITY MONITOR")
    print("=" * 60)
    print(f"  Watching: {WATCH_DIR}")
    print()

    if "--baseline" in sys.argv:
        print("  Creating baseline snapshot...")
        snapshot = build_snapshot(WATCH_DIR)
        save_baseline(snapshot, BASELINE_FILE)
        return None

    baseline = load_baseline(BASELINE_FILE)
    if baseline is None:
        print("  [ERROR] No baseline found.")
        print("  Run with --baseline flag first to create one.")
        return None

    print("  Scanning current state...")
    current = build_snapshot(WATCH_DIR)
    results = compare_snapshots(baseline, current)

    total = len(results["added"]) + len(results["removed"]) + len(results["modified"])

    if total == 0:
        print("  No changes detected. All files match baseline.")
    else:
        print(f"  {total} change(s) detected:\n")
        for f in results["added"]:
            print(f"  [NEW]      {f}")
        for f in results["removed"]:
            print(f"  [DELETED]  {f}")
        for f in results["modified"]:
            print(f"  [MODIFIED] {f}")

    return results


if __name__ == "__main__":
    main()
