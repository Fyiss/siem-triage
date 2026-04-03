"""
classifier.py — Rule-based classification & severity scoring

Each rule defines:
  pattern  : regex matched against the log message
  category : what kind of event this is
  severity : info | low | medium | high | critical
  score    : 0–100 (higher = more dangerous)
  tags     : labels attached to the alert for filtering later

How it works:
  - Every alert is checked against all 15 rules
  - The rule with the highest score wins (sets category + severity)
  - Tags from ALL matching rules are accumulated
"""

import re
from .parser import Alert


RULES = [
    # ── Authentication ────────────────────────────────────────────────────────
    {
        "pattern":  re.compile(r"Failed password|authentication failure|FAILED LOGIN", re.I),
        "category": "auth_failure",
        "severity": "medium",
        "score":    40,
        "tags":     ["auth", "brute-force-candidate"],
    },
    {
        "pattern":  re.compile(r"Invalid user|no such user", re.I),
        "category": "invalid_user",
        "severity": "medium",
        "score":    45,
        "tags":     ["auth", "recon-candidate"],
    },
    {
        "pattern":  re.compile(r"Accepted password|Accepted publickey|session opened for user", re.I),
        "category": "successful_login",
        "severity": "low",
        "score":    15,
        "tags":     ["auth", "login-success"],
    },
    {
        "pattern":  re.compile(r"COMMAND=|sudo:.*COMMAND", re.I),
        "category": "privilege_escalation",
        "severity": "high",
        "score":    70,
        "tags":     ["privesc", "sudo"],
    },
    {
        "pattern":  re.compile(r"su\[.*\].*session opened", re.I),
        "category": "su_session",
        "severity": "medium",
        "score":    50,
        "tags":     ["privesc", "su"],
    },

    # ── Network / SSH ─────────────────────────────────────────────────────────
    {
        "pattern":  re.compile(r"Connection (closed|reset|refused)|Disconnected", re.I),
        "category": "network_disconnect",
        "severity": "info",
        "score":    5,
        "tags":     ["network"],
    },
    {
        "pattern":  re.compile(r"Received disconnect.*preauth", re.I),
        "category": "preauth_disconnect",
        "severity": "low",
        "score":    20,
        "tags":     ["network", "ssh"],
    },
    {
        "pattern":  re.compile(r"Did not receive identification string", re.I),
        "category": "ssh_scanner",
        "severity": "medium",
        "score":    50,
        "tags":     ["network", "scanner", "ssh"],
    },
    {
        "pattern":  re.compile(r"error: maximum authentication attempts exceeded", re.I),
        "category": "brute_force",
        "severity": "high",
        "score":    75,
        "tags":     ["auth", "brute-force"],
    },

    # ── System / Kernel ───────────────────────────────────────────────────────
    {
        "pattern":  re.compile(r"kernel:.*\b(WARN|ERROR|BUG|Oops)\b", re.I),
        "category": "kernel_error",
        "severity": "high",
        "score":    65,
        "tags":     ["kernel", "system-error"],
    },
    {
        "pattern":  re.compile(r"Out of memory|OOM|oom_kill", re.I),
        "category": "oom",
        "severity": "high",
        "score":    70,
        "tags":     ["kernel", "resource"],
    },
    {
        "pattern":  re.compile(r"segfault|segmentation fault", re.I),
        "category": "segfault",
        "severity": "medium",
        "score":    55,
        "tags":     ["crash", "kernel"],
    },
    {
        "pattern":  re.compile(r"systemd.*failed|service.*failed", re.I),
        "category": "service_failure",
        "severity": "medium",
        "score":    45,
        "tags":     ["service", "availability"],
    },

    # ── Intrusion / Malware ───────────────────────────────────────────────────
    {
        "pattern":  re.compile(r"POSSIBLE BREAK-IN ATTEMPT|possible break-in", re.I),
        "category": "breakin_attempt",
        "severity": "critical",
        "score":    95,
        "tags":     ["intrusion", "critical"],
    },
    {
        "pattern":  re.compile(r"rootkit|r00t|/etc/shadow.*modified", re.I),
        "category": "rootkit_indicator",
        "severity": "critical",
        "score":    100,
        "tags":     ["malware", "rootkit", "critical"],
    },
    {
        "pattern":  re.compile(r"REPLACE.*crontab|cron.*REPLACE|crontab.*modified", re.I),
        "category": "persistence_indicator",
        "severity": "high",
        "score":    80,
        "tags":     ["persistence", "suspicious"],
    },
]


# ── Public API ────────────────────────────────────────────────────────────────

def classify(alerts: list[Alert]) -> list[Alert]:
    """
    Apply classification rules to every alert.
    Mutates each alert in-place and returns the same list.
    """
    for alert in alerts:
        _classify_one(alert)
    return alerts


# ── Internal helpers ──────────────────────────────────────────────────────────

def _classify_one(alert: Alert) -> None:
    best_score = 0
    best_rule  = None

    for rule in RULES:
        # Check both the parsed message and the raw line for safety
        if rule["pattern"].search(alert.message) or rule["pattern"].search(alert.raw):
            # Accumulate tags from every matching rule
            for tag in rule["tags"]:
                if tag not in alert.tags:
                    alert.tags.append(tag)
            # Only the highest-scoring rule sets category + severity
            if rule["score"] > best_score:
                best_score = rule["score"]
                best_rule  = rule

    if best_rule:
        alert.category       = best_rule["category"]
        alert.severity       = best_rule["severity"]
        alert.severity_score = best_score
    else:
        alert.category       = "uncategorized"
        alert.severity       = "info"
        alert.severity_score = 0
