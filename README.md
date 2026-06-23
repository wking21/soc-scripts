# SOC Triage Scripts

A collection of Python scripts for blue team security operations — built as part of a hands-on cybersecurity home lab and Google Cybersecurity Professional Certificate project work.

These tools automate three core SOC analyst tasks: detecting brute force login attempts, enriching suspicious IPs with threat intelligence, and monitoring file systems for unauthorized changes. All four scripts are designed to work independently or as a unified triage pipeline.

---

## Scripts

### `brute_force_parser.py`
Reads Linux authentication logs (`auth.log`) and uses regex pattern matching to count failed SSH login attempts per IP address. Any IP that hits the configured threshold gets flagged. The script also cross-references failures against successful logins — an IP that failed repeatedly and then succeeded is treated as a critical escalation signal.

**Key concepts:** `re` module, `defaultdict`, threshold logic, log parsing

---

### `ip_reputation_checker.py`
Takes a list of IP addresses and queries the [AbuseIPDB API](https://www.abuseipdb.com/) for each one. Returns a 0–100 confidence score, country of origin, ISP, and global report count. Converts raw scores into actionable risk labels: CLEAN, LOW, MEDIUM, or HIGH RISK.

**Requires:** A free AbuseIPDB API key — add it to the `API_KEY` variable before running.

**Key concepts:** `requests` library, REST API integration, risk classification logic

---

### `file_integrity_monitor.py`
Monitors a directory for unauthorized file changes using SHA-256 hashing. Run with `--baseline` first to create an initial snapshot of the directory. Subsequent runs compare the current state against the baseline and report any added, removed, or modified files.

**Usage:**
```bash
# Create baseline
python3 file_integrity_monitor.py --baseline

# Check for changes
python3 file_integrity_monitor.py
```

**Key concepts:** `hashlib`, `os.walk`, JSON serialization, snapshot comparison

---

### `soc_triage_pipeline.py`
Combines all three tools into a single correlated triage workflow. Runs the log parser, enriches flagged IPs with reputation data, and performs a file integrity check — then outputs a unified summary report prioritized by risk level.

**Key concepts:** modular design, correlated alert output, multi-source triage

---

## Requirements

```bash
pip install requests
```

All other dependencies (`re`, `os`, `sys`, `json`, `hashlib`) are part of the Python standard library.

---

## Configuration

Before running, update the following variables in each script:

| Variable | Script | Description |
|---|---|---|
| `LOG_FILE` | brute_force_parser.py | Path to your auth.log |
| `THRESHOLD` | brute_force_parser.py | Failed attempts before flagging (default: 5) |
| `API_KEY` | ip_reputation_checker.py | Your free AbuseIPDB API key |
| `WATCH_DIR` | file_integrity_monitor.py | Directory to monitor (default: /etc) |

---

## Home Lab Context

These scripts were developed and tested in a VirtualBox home lab environment running:

- **Kali Linux 2026.1** — attacker/analyst machine
- **Metasploitable2** — intentionally vulnerable target
- **Splunk Enterprise 10.4** — SIEM for log ingestion and search

The brute force parser and file integrity monitor feed directly into the Splunk pipeline via journal log export, enabling end-to-end detection from attack to alert.

---

## Author

**Will King**
SOC analyst candidate | CySA+ in progress | SANS Cyber Academy candidate

[Portfolio](https://wking21.github.io) · [LinkedIn](https://www.linkedin.com/in/william-king-m-ed-7a3649110/)
