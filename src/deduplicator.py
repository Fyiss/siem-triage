"""
deduplicator.py — Noise reduction via time-window deduplication

Problem it solves:
  A single attacker brute-forcing your SSH will generate hundreds of
  identical "Failed password" lines. You don't need 200 alerts — you
  need ONE that says "this happened 200 times in 5 minutes."

How it works:
  1. Build a "fingerprint" for each alert from:
       category + process + src_ip + user
     (same event type, same origin = same fingerprint)

  2. Group all alerts by fingerprint

  3. Within each group, sort by timestamp and apply a rolling window:
     - First occurrence  → kept as the canonical alert
     - Later occurrences within the window → marked as duplicates
     - Occurrences OUTSIDE the window → treated as a new canonical
       (a fresh attack wave hours later is not the same event)

  4. Return only canonical alerts + a stats object
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from .parser import Alert


@dataclass
class DeduplicationResult:
    original_count: int       # how many alerts came in
    deduplicated_count: int   # how many we kept
    suppressed_count: int     # how many we dropped as duplicates
    groups: dict = field(default_factory=dict)  # fingerprint -> [alert ids]


# ── Public API ────────────────────────────────────────────────────────────────

def deduplicate(
    alerts: list[Alert],
    window_minutes: int = 10
) -> tuple[list[Alert], DeduplicationResult]:
    """
    Deduplicate alerts within a rolling time window.

    Args:
        alerts:         classified list of Alert objects
        window_minutes: events with the same fingerprint within this
                        window are collapsed into one

    Returns:
        (kept_alerts, DeduplicationResult)
    """
    window = timedelta(minutes=window_minutes)

    # Step 1 — group by fingerprint
    groups: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        groups[_fingerprint(alert)].append(alert)

    kept       = []
    suppressed = 0
    group_map  = {}

    for fp, group in groups.items():
        # Step 2 — sort oldest first
        group.sort(key=lambda a: _parse_ts(a.timestamp))

        canonical = group[0]
        kept.append(canonical)
        group_map[fp] = [canonical.id]

        # Step 3 — walk the rest of the group
        for alert in group[1:]:
            delta = _parse_ts(alert.timestamp) - _parse_ts(canonical.timestamp)

            if delta <= window:
                # Same attack wave → suppress
                alert.duplicate_of = canonical.id
                suppressed += 1
            else:
                # New wave outside the window → new canonical
                canonical = alert
                kept.append(alert)
                group_map[fp].append(alert.id)

    result = DeduplicationResult(
        original_count     = len(alerts),
        deduplicated_count = len(kept),
        suppressed_count   = suppressed,
        groups             = {k: v for k, v in group_map.items() if len(v) > 1},
    )

    return kept, result


# ── Internal helpers ──────────────────────────────────────────────────────────

def _fingerprint(alert: Alert) -> str:
    """
    Stable string key that identifies semantically identical alerts.
    Two alerts with the same fingerprint = same event from same origin.
    """
    return "|".join([
        alert.category,
        alert.process,
        alert.src_ip or "noip",
        alert.user   or "nouser",
    ])


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.min
