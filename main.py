#!/usr/bin/env python3
"""
main.py — SIEM Alert Triage Automation
CLI entrypoint that runs the full pipeline.

Usage:
    python main.py                              # auto-detect /var/log files
    python main.py sample_logs/demo.log        # single file
    python main.py /var/log/auth.log /var/log/syslog   # multiple files

Optional environment variables for threat intel enrichment:
    ABUSEIPDB_API_KEY=<key>
    VT_API_KEY=<key>
"""

import sys
import os
import time
from pathlib import Path
from collections import Counter

from src import parse_file, classify, deduplicate, enrich_alerts, generate_reports


# Log files to try if no argument is passed
DEFAULT_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/messages",   # Arch Linux
    "/var/log/secure",     # RHEL / Fedora
]

BANNER = r"""
  ███████╗██╗███████╗███╗   ███╗    ████████╗██████╗ ██╗ █████╗  ██████╗ ███████╗
  ██╔════╝██║██╔════╝████╗ ████║    ╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝
  ███████╗██║█████╗  ██╔████╔██║       ██║   ██████╔╝██║███████║██║  ███╗█████╗
  ╚════██║██║██╔══╝  ██║╚██╔╝██║       ██║   ██╔══██╗██║██╔══██║██║   ██║██╔══╝
  ███████║██║███████╗██║ ╚═╝ ██║       ██║   ██║  ██║██║██║  ██║╚██████╔╝███████╗
  ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝       ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
  Alert Triage Automation  |  SecOps Portfolio Project
"""


def main():
    print(BANNER)
    t0 = time.time()

    # ── Resolve input files ───────────────────────────────────────────────────
    log_paths = sys.argv[1:]

    if not log_paths:
        log_paths = [p for p in DEFAULT_LOG_PATHS if Path(p).exists()]
        if not log_paths:
            print("[!] No log files found. Pass a path explicitly:")
            print("    python main.py sample_logs/demo.log")
            sys.exit(1)

    print(f"[+] Input: {', '.join(log_paths)}\n")

    # ── Step 1: Parse ─────────────────────────────────────────────────────────
    print("[1/4] Parsing log files...")
    all_alerts = []
    for path in log_paths:
        alerts = parse_file(path)
        print(f"      {path}: {len(alerts)} lines parsed")
        all_alerts.extend(alerts)

    print(f"      Total: {len(all_alerts)} alerts\n")

    if not all_alerts:
        print("[!] No parseable lines found. Exiting.")
        sys.exit(0)

    # ── Step 2: Classify ──────────────────────────────────────────────────────
    print("[2/4] Classifying & scoring...")
    classify(all_alerts)

    sev = Counter(a.severity for a in all_alerts)
    print(
        f"      🔴 critical={sev['critical']}  "
        f"🟠 high={sev['high']}  "
        f"🟡 medium={sev['medium']}  "
        f"🔵 low={sev['low']}  "
        f"⚪ info={sev['info']}\n"
    )

    # ── Step 3: Deduplicate ───────────────────────────────────────────────────
    print("[3/4] Deduplicating (10-min window)...")
    deduped, dedup_result = deduplicate(all_alerts, window_minutes=10)
    print(
        f"      {dedup_result.original_count} → {dedup_result.deduplicated_count} "
        f"(suppressed {dedup_result.suppressed_count} duplicates)\n"
    )

    # ── Step 4: Enrich ────────────────────────────────────────────────────────
    unique_ips = {a.src_ip for a in deduped if a.src_ip}
    print(f"[4/4] Enriching {len(unique_ips)} unique IPs...")

    has_keys = os.environ.get("ABUSEIPDB_API_KEY") or os.environ.get("VT_API_KEY")
    if not has_keys:
        print("      ⚠  No API keys set — skipping live enrichment.")
        print("         Set ABUSEIPDB_API_KEY and/or VT_API_KEY to enable.\n")

    enrichment = enrich_alerts(deduped)

    # ── Generate reports ──────────────────────────────────────────────────────
    print("[✓] Generating reports...")
    json_path, md_path = generate_reports(deduped, dedup_result, enrichment)

    elapsed = time.time() - t0
    print(f"\n{'=' * 60}")
    print(f"  ✅ Done in {elapsed:.1f}s")
    print(f"  📄 JSON → {json_path}")
    print(f"  📝 MD   → {md_path}")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()