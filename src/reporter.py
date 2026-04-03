"""
reporter.py — JSON + Markdown report generation

Produces two files per run:
  reports/report_<timestamp>.json   — full machine-readable data
  reports/report_<timestamp>.md     — human-readable SOC summary

JSON report structure:
  {
    "generated_at": "...",
    "summary":      { severity counts, top categories, top IPs },
    "deduplication": { stats from deduplicator },
    "enrichment":    { ip -> EnrichmentResult },
    "alerts":        [ all Alert objects ]
  }

Markdown report sections:
  1. Executive Summary     — key numbers at a glance
  2. Severity Breakdown    — visual bar chart in text
  3. Top Event Categories  — what kinds of events dominated
  4. Top Source IPs        — with threat intel scores if available
  5. High / Critical Alerts — full detail on the dangerous ones
  6. Deduplication Groups  — which events were collapsed
"""

import json
from datetime import datetime
from pathlib import Path
from dataclasses import asdict
from collections import Counter
from .parser import Alert
from .deduplicator import DeduplicationResult
from .enricher import EnrichmentResult


SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# ── Public API ────────────────────────────────────────────────────────────────

def generate_reports(
    alerts: list[Alert],
    dedup_result: DeduplicationResult,
    enrichment: dict[str, EnrichmentResult],
    output_dir: str = "reports",
) -> tuple[str, str]:
    """
    Write JSON and Markdown reports to output_dir.

    Returns:
        (json_path, md_path)
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = str(out / f"report_{ts}.json")
    md_path   = str(out / f"report_{ts}.md")

    _write_json(alerts, dedup_result, enrichment, json_path)
    _write_markdown(alerts, dedup_result, enrichment, md_path)

    return json_path, md_path


# ── JSON ──────────────────────────────────────────────────────────────────────

def _write_json(alerts, dedup_result, enrichment, path):
    payload = {
        "generated_at":  datetime.now().isoformat(),
        "summary":       _build_summary(alerts, dedup_result),
        "deduplication": asdict(dedup_result),
        "enrichment":    {ip: asdict(r) for ip, r in enrichment.items()},
        "alerts":        [asdict(a) for a in alerts],
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2, default=str)


# ── Markdown ──────────────────────────────────────────────────────────────────

def _build_summary(alerts, dedup):
    sev_counts = Counter(a.severity for a in alerts)
    cat_counts = Counter(a.category for a in alerts)
    ip_counts  = Counter(a.src_ip for a in alerts if a.src_ip)
    return {
        "total_alerts":       len(alerts),
        "original_raw_lines": dedup.original_count,
        "suppressed_dupes":   dedup.suppressed_count,
        "severity_breakdown": {s: sev_counts.get(s, 0) for s in SEVERITY_ORDER},
        "top_categories":     cat_counts.most_common(10),
        "top_source_ips":     ip_counts.most_common(10),
    }


def _write_markdown(alerts, dedup_result, enrichment, path):
    summary = _build_summary(alerts, dedup_result)
    now     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "# 🛡️ SIEM Alert Triage Report",
        f"> Generated: `{now}`",
        "",
        "---",
        "",
        "## 📊 Executive Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Raw log lines parsed    | {dedup_result.original_count} |",
        f"| Unique alerts (deduped) | {summary['total_alerts']} |",
        f"| Suppressed duplicates   | {summary['suppressed_dupes']} |",
        "",
        "## Severity Breakdown",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]

    for sev in SEVERITY_ORDER:
        count = summary["severity_breakdown"].get(sev, 0)
        if count:
            bar = "█" * min(count, 30)
            lines.append(f"| {SEVERITY_EMOJI[sev]} {sev.upper():<10} | {bar} {count} |")

    # Top categories
    lines += [
        "",
        "---",
        "",
        "## 🔍 Top Event Categories",
        "",
        "| Category | Count |",
        "|----------|-------|",
    ]
    for cat, cnt in summary["top_categories"]:
        lines.append(f"| `{cat}` | {cnt} |")

    # Top source IPs
    if summary["top_source_ips"]:
        lines += [
            "",
            "---",
            "",
            "## 🌐 Top Source IPs",
            "",
            "| IP | Hits | AbuseIPDB Score | Country | VT Malicious |",
            "|----|------|----------------|---------|--------------|",
        ]
        for ip, count in summary["top_source_ips"]:
            enr         = enrichment.get(ip)
            abuse_score = enr.abuseipdb_score         if enr and enr.abuseipdb_score         is not None else "—"
            country     = enr.abuseipdb_country       if enr and enr.abuseipdb_country                  else "—"
            vt_mal      = enr.vt_malicious             if enr and enr.vt_malicious            is not None else "—"
            lines.append(f"| `{ip}` | {count} | {abuse_score} | {country} | {vt_mal} |")

    # High / Critical alert details
    critical_alerts = [a for a in alerts if a.severity in ("critical", "high")]
    if critical_alerts:
        lines += [
            "",
            "---",
            "",
            f"## 🚨 High / Critical Alerts ({len(critical_alerts)})",
            "",
        ]
        for a in sorted(critical_alerts, key=lambda x: -x.severity_score):
            emoji = SEVERITY_EMOJI[a.severity]
            lines += [
                f"### {emoji} `{a.category}` — score {a.severity_score}",
                f"- **Time:**    `{a.timestamp}`",
                f"- **Host:**    `{a.host}`  |  **Process:** `{a.process}`",
            ]
            if a.src_ip:
                lines.append(f"- **Source IP:** `{a.src_ip}`")
            if a.user:
                lines.append(f"- **User:**      `{a.user}`")
            if a.tags:
                lines.append(f"- **Tags:**      {', '.join(f'`{t}`' for t in a.tags)}")
            lines += [
                f"- **Message:**  `{a.message[:200]}`",
                "",
            ]

    # Deduplication groups
    if dedup_result.groups:
        lines += [
            "---",
            "",
            "## 🔄 Deduplication Groups",
            "",
            "| Fingerprint | Occurrences |",
            "|-------------|-------------|",
        ]
        for fp, ids in list(dedup_result.groups.items())[:20]:
            lines.append(f"| `{fp[:60]}` | {len(ids)} |")

    lines += [
        "",
        "---",
        "",
        "*Generated by siem-triage. "
        "Set `ABUSEIPDB_API_KEY` and `VT_API_KEY` for full threat intel enrichment.*",
    ]

    with open(path, "w") as f:
        f.write("\n".join(lines))
