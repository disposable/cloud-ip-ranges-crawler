"""Integration tests for cloud-ip-ranges.

Integration tests make real HTTP requests to external APIs and validate
the full workflow against live data. These tests are skipped by default
and can be run with: pytest -m integration

Integration tests require:
- Internet connectivity
- Rate limiting considerations
- No API keys (only public endpoints)
"""
