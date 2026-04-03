"""
enricher.py — Threat intel enrichment via AbuseIPDB + VirusTotal

What it does:
  Takes every unique source IP found across all alerts and looks it up
  on two free threat intelligence databases:

  - AbuseIPDB  : community-reported abuse scores, country, ISP
  - VirusTotal : antivirus engine verdicts on the IP

  Results are attached to the report so analysts immediately know
  whether a suspicious IP is a known bad actor.

API keys (optional, set as environment variables):
  ABUSEIPDB_API_KEY
  VT_API_KEY

  Without keys the tool still works — enrichment fields show None
  and the report marks them as "api_key_missing".

Rate limiting:
  A simple sleep between calls keeps us inside free-tier limits
  (AbuseIPDB: 1000/day, VirusTotal: 500/day).
"""

import os
import time
import requests
from dataclasses import dataclass
from typing import Optional
from .parser import Alert


@dataclass
class EnrichmentResult:
    ip: str

    # AbuseIPDB fields
    abuseipdb_score:         Optional[int] = None   # 0–100, higher = more abusive
    abuseipdb_country:       Optional[str] = None
    abuseipdb_isp:           Optional[str] = None
    abuseipdb_total_reports: Optional[int] = None

    # VirusTotal fields
    vt_malicious:    Optional[int] = None   # number of engines flagging as malicious
    vt_suspicious:   Optional[int] = None
    vt_last_analysis: Optional[str] = None

    # Meta
    error:  Optional[str] = None
    source: str = "none"           # "none" | "abuseipdb" | "virustotal" | "both"


# Minimum seconds between API calls — respects free-tier rate limits
_MIN_INTERVAL = 1.5
_last_call: float = 0.0

# Simple in-memory cache so we never look up the same IP twice
_cache: dict[str, EnrichmentResult] = {}


# ── Public API ────────────────────────────────────────────────────────────────

def enrich_alerts(alerts: list[Alert]) -> dict[str, EnrichmentResult]:
    """
    Enrich all unique source IPs found in the alert list.

    Returns:
        dict mapping ip -> EnrichmentResult
    """
    unique_ips = {a.src_ip for a in alerts if a.src_ip}

    results = {}
    for ip in unique_ips:
        print(f"  [~] Enriching {ip} ...")
        results[ip] = _enrich_ip(ip)

    return results


# ── Internal helpers ──────────────────────────────────────────────────────────

def _enrich_ip(ip: str) -> EnrichmentResult:
    if ip in _cache:
        return _cache[ip]

    result    = EnrichmentResult(ip=ip)
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY")
    vt_key    = os.environ.get("VT_API_KEY")

    if not abuse_key and not vt_key:
        result.error  = "api_key_missing"
        result.source = "none"
        _cache[ip] = result
        return result

    # AbuseIPDB
    if abuse_key:
        try:
            data = _query_abuseipdb(ip, abuse_key)
            result.abuseipdb_score         = data.get("abuseConfidenceScore")
            result.abuseipdb_country       = data.get("countryCode")
            result.abuseipdb_isp           = data.get("isp")
            result.abuseipdb_total_reports = data.get("totalReports")
            result.source = "abuseipdb"
        except Exception as e:
            result.error = f"AbuseIPDB: {e}"

    # VirusTotal
    if vt_key:
        try:
            data = _query_virustotal(ip, vt_key)
            stats = data.get("last_analysis_stats", {})
            result.vt_malicious    = stats.get("malicious", 0)
            result.vt_suspicious   = stats.get("suspicious", 0)
            result.vt_last_analysis = data.get("last_analysis_date")
            result.source = "both" if abuse_key else "virustotal"
        except Exception as e:
            result.error = (result.error or "") + f" | VirusTotal: {e}"

    _cache[ip] = result
    return result


def _throttle():
    """Sleep just enough to stay inside free-tier rate limits."""
    global _last_call
    elapsed = time.time() - _last_call
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)
    _last_call = time.time()


def _query_abuseipdb(ip: str, api_key: str) -> dict:
    _throttle()
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json().get("data", {})


def _query_virustotal(ip: str, api_key: str) -> dict:
    _throttle()
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": api_key},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json().get("data", {}).get("attributes", {})
