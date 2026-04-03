"""
src/__init__.py — Public API for the siem-triage package

Importing from src gives you everything you need to run the pipeline:

    from src import parse_file, classify, deduplicate, enrich_alerts, generate_reports

Pipeline order:
    1. parse_file()       → list[Alert]
    2. classify()         → list[Alert]   (mutates in place)
    3. deduplicate()      → (list[Alert], DeduplicationResult)
    4. enrich_alerts()    → dict[str, EnrichmentResult]
    5. generate_reports() → (json_path, md_path)
"""

from .parser      import parse_file, Alert
from .classifier  import classify
from .deduplicator import deduplicate, DeduplicationResult
from .enricher    import enrich_alerts, EnrichmentResult
from .reporter    import generate_reports
