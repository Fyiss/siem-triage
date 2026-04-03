"""
tests/test_triage.py — Unit tests for parser, classifier, deduplicator

Run with:
    pytest tests/ -v

Coverage:
    parser       — file reading, regex extraction, missing file handling
    classifier   — each major rule, tag accumulation, unknown events
    deduplicator — duplicate collapse, window boundary, different IPs
"""

import sys
from pathlib import Path

# Make sure imports work when running from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parser import Alert, parse_file
from src.classifier import classify
from src.deduplicator import deduplicate


# ── Helpers ───────────────────────────────────────────────────────────────────

def _alert(msg: str, aid: str = "t001", process: str = "sshd") -> Alert:
    """Create a minimal Alert with just a message for classifier testing."""
    return Alert(
        id          = aid,
        timestamp   = "2024-01-15T08:00:00",
        source_file = "test",
        raw         = msg,
        message     = msg,
        host        = "srv01",
        process     = process,
    )


def _classified_alert(
    aid: str,
    ts: str,
    category: str,
    ip: str = None,
    user: str = None,
    process: str = "sshd",
) -> Alert:
    """Create a minimal Alert with classification fields set, for dedup testing."""
    a = Alert(
        id          = aid,
        timestamp   = ts,
        source_file = "test",
        raw         = "",
        message     = "",
        host        = "srv01",
        process     = process,
        category    = category,
        src_ip      = ip,
        user        = user,
    )
    return a


# ── Parser tests ──────────────────────────────────────────────────────────────

def test_parse_returns_alerts():
    alerts = parse_file("sample_logs/demo.log")
    assert len(alerts) > 10

def test_parse_all_are_alert_objects():
    alerts = parse_file("sample_logs/demo.log")
    assert all(isinstance(a, Alert) for a in alerts)

def test_parse_extracts_ip():
    alerts = parse_file("sample_logs/demo.log")
    ips = [a.src_ip for a in alerts if a.src_ip]
    assert "45.33.32.156" in ips

def test_parse_extracts_user():
    alerts = parse_file("sample_logs/demo.log")
    users = [a.user for a in alerts if a.user]
    assert len(users) > 0

def test_parse_populates_host():
    alerts = parse_file("sample_logs/demo.log")
    assert all(a.host != "" for a in alerts)

def test_parse_populates_timestamp():
    alerts = parse_file("sample_logs/demo.log")
    assert all(a.timestamp != "" for a in alerts)

def test_parse_missing_file_returns_empty():
    result = parse_file("/nonexistent/path.log")
    assert result == []


# ── Classifier tests ──────────────────────────────────────────────────────────

def test_classify_failed_password():
    a = _alert("Failed password for root from 1.2.3.4 port 22 ssh2")
    classify([a])
    assert a.category == "auth_failure"
    assert a.severity == "medium"
    assert a.severity_score == 40

def test_classify_brute_force():
    a = _alert("error: maximum authentication attempts exceeded for root from 1.2.3.4")
    classify([a])
    assert a.category == "brute_force"
    assert a.severity == "high"
    assert a.severity_score >= 70

def test_classify_invalid_user():
    a = _alert("Invalid user admin from 5.5.5.5 port 22")
    classify([a])
    assert a.category == "invalid_user"
    assert a.severity == "medium"

def test_classify_sudo_escalation():
    a = _alert("deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash", process="sudo")
    classify([a])
    assert a.category == "privilege_escalation"
    assert a.severity == "high"

def test_classify_breakin_attempt():
    a = _alert("POSSIBLE BREAK-IN ATTEMPT from 185.220.101.50")
    classify([a])
    assert a.category == "breakin_attempt"
    assert a.severity == "critical"
    assert a.severity_score >= 90

def test_classify_oom():
    a = _alert("Out of memory: Kill process 1234 (java) score 900")
    classify([a])
    assert a.category == "oom"
    assert a.severity == "high"

def test_classify_segfault():
    a = _alert("segfault at 0 ip 00007f1234 sp 00007fff error 4")
    classify([a])
    assert a.category == "segfault"
    assert a.severity == "medium"

def test_classify_persistence():
    a = _alert("root REPLACE crontabs/root", process="cron")
    classify([a])
    assert a.category == "persistence_indicator"
    assert a.severity == "high"

def test_classify_service_failure():
    a = _alert("nginx.service: Failed with result signal", process="systemd")
    classify([a])
    assert a.category == "service_failure"

def test_classify_unknown_is_uncategorized():
    a = _alert("totally normal startup message nothing to see here")
    classify([a])
    assert a.category == "uncategorized"
    assert a.severity == "info"
    assert a.severity_score == 0

def test_classify_tags_accumulate():
    # Matches both auth_failure and invalid_user — should get tags from both
    a = _alert("Failed password for invalid user admin from 1.2.3.4")
    classify([a])
    assert len(a.tags) >= 2

def test_classify_highest_score_wins():
    # brute_force (75) should beat auth_failure (40)
    a = _alert("error: maximum authentication attempts exceeded for root from 1.2.3.4")
    classify([a])
    assert a.category == "brute_force"
    assert a.severity_score == 75


# ── Deduplicator tests ────────────────────────────────────────────────────────

def test_dedup_collapses_same_ip():
    alerts = [
        _classified_alert("a1", "2024-01-15T08:01:00", "auth_failure", ip="1.2.3.4"),
        _classified_alert("a2", "2024-01-15T08:02:00", "auth_failure", ip="1.2.3.4"),
        _classified_alert("a3", "2024-01-15T08:03:00", "auth_failure", ip="1.2.3.4"),
    ]
    kept, result = deduplicate(alerts, window_minutes=10)
    assert len(kept) == 1
    assert result.suppressed_count == 2

def test_dedup_keeps_different_ips():
    alerts = [
        _classified_alert("a1", "2024-01-15T08:01:00", "auth_failure", ip="1.1.1.1"),
        _classified_alert("a2", "2024-01-15T08:01:30", "auth_failure", ip="2.2.2.2"),
    ]
    kept, result = deduplicate(alerts)
    assert len(kept) == 2
    assert result.suppressed_count == 0

def test_dedup_outside_window_is_new_canonical():
    alerts = [
        _classified_alert("a1", "2024-01-15T08:00:00", "auth_failure", ip="1.2.3.4"),
        _classified_alert("a2", "2024-01-15T09:00:00", "auth_failure", ip="1.2.3.4"),  # 60 min later
    ]
    kept, result = deduplicate(alerts, window_minutes=10)
    assert len(kept) == 2
    assert result.suppressed_count == 0

def test_dedup_marks_duplicate_of():
    alerts = [
        _classified_alert("a1", "2024-01-15T08:01:00", "auth_failure", ip="1.2.3.4"),
        _classified_alert("a2", "2024-01-15T08:02:00", "auth_failure", ip="1.2.3.4"),
    ]
    deduplicate(alerts, window_minutes=10)
    assert alerts[1].duplicate_of == "a1"

def test_dedup_counts_are_consistent():
    alerts = parse_file("sample_logs/demo.log")
    classify(alerts)
    kept, result = deduplicate(alerts)
    assert result.original_count == len(alerts)
    assert result.deduplicated_count == len(kept)
    assert result.suppressed_count == result.original_count - result.deduplicated_count
