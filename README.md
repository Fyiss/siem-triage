# 🛡️ siem-triage

A modular Python CLI that ingests raw Linux system logs, classifies security events, suppresses duplicate noise, enriches suspicious IPs with threat intel, and produces structured JSON + Markdown reports.

Built to mirror real SecOps SOC workflows.

---

## Demo

```bash
$ python main.py sample_logs/demo.log

[1/4] Parsing log files...
      sample_logs/demo.log: 33 lines parsed

[2/4] Classifying & scoring alerts...
      🔴 critical=1  🟠 high=4  🟡 medium=18  🔵 low=5  ⚪ info=5

[3/4] Deduplicating (10-min window)...
      33 → 26 (suppressed 7 duplicates)

[4/4] Enriching 5 unique IPs...

✅ Done in 0.3s
📄 JSON  → reports/report_20240115_080100.json
📝 MD    → reports/report_20240115_080100.md
```

---

## Features

| Module | What it does |
|--------|-------------|
| `parser.py` | Ingests `/var/log/auth.log`, `syslog`, `kern.log` — normalizes into typed Alert objects |
| `classifier.py` | 15-rule engine assigns category, severity (`info`→`critical`), and score (0–100) |
| `deduplicator.py` | Rolling time-window dedup collapses repeated events; flags originals vs. noise |
| `enricher.py` | Queries AbuseIPDB + VirusTotal for each unique source IP |
| `reporter.py` | Outputs `.json` (machine-readable) + `.md` (SOC-ready summary) |

---

## Quickstart

```bash
# Clone
git clone https://github.com/<you>/siem-triage
cd siem-triage

# Install dependencies
pip install -r requirements.txt

# Run on demo data (no setup needed)
python main.py sample_logs/demo.log

# Run on real system logs
python main.py /var/log/auth.log /var/log/syslog

# With threat intel enrichment (optional)
export ABUSEIPDB_API_KEY=your_key
export VT_API_KEY=your_key
python main.py sample_logs/demo.log
```

---

## Project Structure

```
siem-triage/
├── src/
│   ├── parser.py           # Log ingestion & normalization
│   ├── classifier.py       # Rule-based classification & scoring
│   ├── deduplicator.py     # Noise reduction
│   ├── enricher.py         # AbuseIPDB + VirusTotal enrichment
│   └── reporter.py         # JSON + Markdown report generation
├── tests/
│   └── test_triage.py      # Unit tests (pytest)
├── sample_logs/
│   └── demo.log            # Realistic sample data
├── main.py                 # CLI entrypoint
└── requirements.txt
```

---

## Alert Categories

| Category | Severity | Description |
|----------|----------|-------------|
| `brute_force` | 🟠 high | Max auth attempts exceeded |
| `breakin_attempt` | 🔴 critical | `POSSIBLE BREAK-IN ATTEMPT` in logs |
| `rootkit_indicator` | 🔴 critical | Signs of rootkit / shadow file modification |
| `privilege_escalation` | 🟠 high | `sudo` / `su` session events |
| `persistence_indicator` | 🟠 high | Crontab modifications |
| `auth_failure` | 🟡 medium | Failed password attempts |
| `invalid_user` | 🟡 medium | Login attempts for non-existent users |
| `ssh_scanner` | 🟡 medium | No identification string (port scanner) |
| `oom` | 🟠 high | Out-of-memory process kills |
| `segfault` | 🟡 medium | Segmentation faults |
| `service_failure` | 🟡 medium | systemd service failures |

---

## API Keys (Optional)

Free keys for threat intel enrichment:

- [AbuseIPDB](https://www.abuseipdb.com/register) — 1,000 checks/day
- [VirusTotal](https://www.virustotal.com/gui/join-us) — 500 lookups/day

The tool works fully without them — enrichment fields show `—` in reports.

---

## Running Tests

```bash
python -m pytest tests/ -v
```

---

## Tech Stack

- Python 3.10+
- `requests` — API calls
- `pytest` — testing
- No heavy frameworks — pure stdlib where possible

---

*Part of a SecOps portfolio. Covers log analysis, automation scripting, API integration, and security event triage.*
