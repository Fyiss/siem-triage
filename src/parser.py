"""
parser.py — Log ingestion & normalization

Reads raw Linux log files and converts each line into a structured
Alert object. Supports auth.log, syslog, kern.log format.

Standard syslog line format:
  Jan  1 12:00:00 hostname process[pid]: message
"""

import re
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Alert:
    id: str                          # unique identifier e.g. "auth_000042"
    timestamp: str                   # ISO format: 2024-01-15T08:01:22
    source_file: str                 # which log file this came from
    raw: str                         # original unmodified log line
    host: str = ""                   # server hostname
    process: str = ""                # e.g. sshd, sudo, kernel
    pid: str = ""                    # process ID
    message: str = ""               # the actual log message
    src_ip: Optional[str] = None    # extracted source IP if present
    user: Optional[str] = None      # extracted username if present
    # fields filled in by later modules:
    category: str = "uncategorized"
    severity: str = "info"           # info | low | medium | high | critical
    severity_score: int = 0          # 0–100
    tags: list = field(default_factory=list)
    duplicate_of: Optional[str] = None


# ── Regex patterns ────────────────────────────────────────────────────────────

# Matches standard syslog format
SYSLOG_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.+)$'
)

IP_RE   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
USER_RE = re.compile(r'(?:user|for)\s+(\w+)', re.IGNORECASE)


# ── Public API ────────────────────────────────────────────────────────────────

def parse_file(path: str) -> list[Alert]:
    """
    Parse a log file and return a list of Alert objects.
    Unrecognized lines are silently skipped.
    """
    alerts = []
    p = Path(path)

    if not p.exists():
        print(f"[!] File not found: {path}")
        return alerts

    year = datetime.now().year

    with open(p, "r", errors="replace") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            alert = _parse_line(line, str(p), f"{p.stem}_{i:06d}", year)
            if alert:
                alerts.append(alert)

    return alerts


# ── Internal helpers ──────────────────────────────────────────────────────────

def _parse_line(line: str, source: str, alert_id: str, year: int) -> Optional[Alert]:
    m = SYSLOG_RE.match(line)
    if not m:
        return None

    g = m.groupdict()

    try:
        ts = datetime.strptime(
            f"{year} {g['month']} {g['day'].zfill(2)} {g['time']}",
            "%Y %b %d %H:%M:%S"
        ).isoformat()
    except ValueError:
        ts = line[:15]

    msg  = g["message"]
    ips  = IP_RE.findall(msg)
    users = USER_RE.findall(msg)

    return Alert(
        id          = alert_id,
        timestamp   = ts,
        source_file = source,
        raw         = line,
        host        = g["host"],
        process     = g["process"],
        pid         = g["pid"] or "",
        message     = msg,
        src_ip      = ips[0] if ips else None,
        user        = users[0] if users else None,
    )
