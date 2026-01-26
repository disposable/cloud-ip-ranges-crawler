"""Unit tests for seed_rdap_registry.py transform."""

import ipaddress
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.cloud_ip_ranges import CloudIPRanges
from src.transforms.seed_rdap_registry import _xml_find_text, transform

from tests.unit.conftest import FakeResponse


def test_xml_find_text_success() -> None:
    """Test _xml_find_text finds a matching tag."""
    from xml.etree.ElementTree import Element

    root = Element("root")
    child = Element("{http://example.com}updateDate")
    child.text = "2025-01-01T00:00:00Z"
    root.append(child)

    assert _xml_find_text(root, "updateDate") == "2025-01-01T00:00:00Z"


def test_xml_find_text_missing() -> None:
    """Test _xml_find_text returns None when tag is missing."""
    from xml.etree.ElementTree import Element

    root = Element("root")
    child = Element("{http://example.com}otherTag")
    child.text = "value"
    root.append(child)

    assert _xml_find_text(root, "updateDate") is None


def test_transform_seed_rdap_registry_happy_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test full happy path with JSON responses."""
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"test": ["1.2.3.0/24"]}

    # Mock RDAP response
    rdap_resp = FakeResponse(json_data={
        "entities": [
            {"handle": "ORG-EXAMPLE", "roles": ["registrant"]},
        ]
    })

    # Mock ARIN org JSON response
    org_resp = FakeResponse(json_data={
        "org": {"updateDate": "2025-01-01T00:00:00Z"}
    })

    # Mock ARIN nets JSON response
    nets_resp = FakeResponse(json_data={
        "nets": {
            "netRef": [
                {"@startAddress": "1.2.3.0", "@endAddress": "1.2.3.255"},
                {"startAddress": "2606:4700::", "endAddress": "2606:4700::ffff"},
            ]
        }
    })

    def fake_get(url: str, timeout: int = 10):
        if url.endswith("/registry/ip/1.2.3.0"):
            return rdap_resp
        if url.endswith("/rest/org/ORG-EXAMPLE"):
            return org_resp
        if url.endswith("/rest/org/ORG-EXAMPLE/nets"):
            return nets_resp
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(crawler.session, "get", fake_get)

    result = transform(crawler, [rdap_resp], "test")
    assert result["method"] == "rdap_registry"
    assert result["coverage_notes"] == "Provider-owned netblocks (registry), not necessarily the full set of edge/egress IPs"
    assert result["source_updated_at"] == "2025-01-01T00:00:00Z"
    assert "1.2.3.0/24" in result["ipv4"]
    assert any("2606:4700::" in ip for ip in result["ipv6"])


def test_transform_seed_rdap_registry_xml_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test XML fallback when JSON parsing fails."""
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"test": ["1.2.3.0/24"]}

    rdap_resp = FakeResponse(json_data={
        "entities": [
            {"handle": "ORG-XML", "roles": ["registrant"]},
        ]
    })

    # XML responses
    org_xml = """<?xml version="1.0"?>
    <org xmlns="https://www.arin.net/whoisrws/core/v1">
        <updateDate>2025-01-02T00:00:00Z</updateDate>
    </org>"""

    nets_xml = """<?xml version="1.0"?>
    <nets xmlns="https://www.arin.net/whoisrws/core/v1">
        <netRef startAddress="2.2.2.0" endAddress="2.2.2.255" />
    </nets>"""

    def fake_get(url: str, timeout: int = 10):
        if url.endswith("/registry/ip/1.2.3.0"):
            return rdap_resp
        if url.endswith("/rest/org/ORG-XML"):
            return FakeResponse(text=org_xml)
        if url.endswith("/rest/org/ORG-XML/nets"):
            return FakeResponse(text=nets_xml)
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(crawler.session, "get", fake_get)

    result = transform(crawler, [rdap_resp], "test")
    assert result["source_updated_at"] == "2025-01-02T00:00:00Z"
    assert "2.2.2.0/24" in result["ipv4"]


def test_transform_seed_rdap_registry_no_registrant_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test error when no registrant entity is found."""
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"test": ["1.2.3.0/24"]}

    rdap_resp = FakeResponse(json_data={
        "entities": [
            {"handle": "ORG-TECHNICAL", "roles": ["technical"]},
        ]
    })

    def fake_get(url: str, timeout: int = 10):
        if url.endswith("/registry/ip/1.2.3.0"):
            return rdap_resp
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(crawler.session, "get", fake_get)

    with pytest.raises(RuntimeError, match="Failed to find any ARIN org handles"):
        transform(crawler, [rdap_resp], "test")


def test_transform_seed_rdap_registry_nets_json_parsing_error_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test error when both JSON and XML parsing fail for nets."""
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"test": ["1.2.3.0/24"]}

    rdap_resp = FakeResponse(json_data={
        "entities": [
            {"handle": "ORG-ERROR", "roles": ["registrant"]},
        ]
    })

    org_resp = FakeResponse(json_data={"org": {"updateDate": "2025-01-01T00:00:00Z"}})
    nets_resp = FakeResponse(text="not valid json or xml")

    def fake_get(url: str, timeout: int = 10):
        if url.endswith("/registry/ip/1.2.3.0"):
            return rdap_resp
        if url.endswith("/rest/org/ORG-ERROR"):
            return org_resp
        if url.endswith("/rest/org/ORG-ERROR/nets"):
            return nets_resp
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(crawler.session, "get", fake_get)

    with pytest.raises(RuntimeError, match="ARIN nets could not be parsed for ORG-ERROR"):
        transform(crawler, [rdap_resp], "test")


def test_transform_seed_rdap_registry_invalid_ip_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that invalid IP addresses are skipped."""
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"test": ["1.2.3.0/24"]}

    rdap_resp = FakeResponse(json_data={
        "entities": [
            {"handle": "ORG-INVALID", "roles": ["registrant"]},
        ]
    })

    org_resp = FakeResponse(json_data={"org": {"updateDate": "2025-01-01T00:00:00Z"}})
    nets_resp = FakeResponse(json_data={
        "nets": {
            "netRef": [
                {"@startAddress": "invalid.ip", "@endAddress": "1.2.3.255"},
                {"@startAddress": "3.4.5.0", "@endAddress": "3.4.5.255"},
            ]
        }
    })

    def fake_get(url: str, timeout: int = 10):
        if url.endswith("/registry/ip/1.2.3.0"):
            return rdap_resp
        if url.endswith("/rest/org/ORG-INVALID"):
            return org_resp
        if url.endswith("/rest/org/ORG-INVALID/nets"):
            return nets_resp
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(crawler.session, "get", fake_get)

    result = transform(crawler, [rdap_resp], "test")
    assert "3.4.5.0/24" in result["ipv4"]
    assert len(result["ipv4"]) == 1  # Only the valid range


def test_transform_seed_rdap_registry_duplicate_ranges_deduped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that duplicate ranges are deduplicated."""
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"test": ["1.2.3.0/24"]}

    rdap_resp = FakeResponse(json_data={
        "entities": [
            {"handle": "ORG-DUP", "roles": ["registrant"]},
        ]
    })

    org_resp = FakeResponse(json_data={"org": {"updateDate": "2025-01-01T00:00:00Z"}})
    nets_resp = FakeResponse(json_data={
        "nets": {
            "netRef": [
                {"@startAddress": "4.5.6.0", "@endAddress": "4.5.6.255"},
                {"@startAddress": "4.5.6.0", "@endAddress": "4.5.6.255"},  # duplicate
            ]
        }
    })

    def fake_get(url: str, timeout: int = 10):
        if url.endswith("/registry/ip/1.2.3.0"):
            return rdap_resp
        if url.endswith("/rest/org/ORG-DUP"):
            return org_resp
        if url.endswith("/rest/org/ORG-DUP/nets"):
            return nets_resp
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(crawler.session, "get", fake_get)

    result = transform(crawler, [rdap_resp], "test")
    assert result["ipv4"].count("4.5.6.0/24") == 1


def test_transform_seed_rdap_registry_mixed_json_xml_nets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test mixed JSON org and XML nets."""
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"test": ["1.2.3.0/24"]}

    rdap_resp = FakeResponse(json_data={
        "entities": [
            {"handle": "ORG-MIXED", "roles": ["registrant"]},
        ]
    })

    org_resp = FakeResponse(json_data={"org": {"updateDate": "2025-01-01T00:00:00Z"}})

    nets_xml = """<?xml version="1.0"?>
    <nets xmlns="https://www.arin.net/whoisrws/core/v1">
        <netRef startAddress="5.6.7.0" endAddress="5.6.7.255" />
    </nets>"""

    def fake_get(url: str, timeout: int = 10):
        if url.endswith("/registry/ip/1.2.3.0"):
            return rdap_resp
        if url.endswith("/rest/org/ORG-MIXED"):
            return org_resp
        if url.endswith("/rest/org/ORG-MIXED/nets"):
            return FakeResponse(text=nets_xml)
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(crawler.session, "get", fake_get)

    result = transform(crawler, [rdap_resp], "test")
    assert "5.6.7.0/24" in result["ipv4"]


def test_transform_seed_rdap_registry_edge_cases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test edge cases: non-dict entities, org parse failure, non-dict nets."""
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"test": ["1.2.3.0/24"]}

    # RDAP with non-dict entity and a valid registrant
    rdap_resp = FakeResponse(json_data={
        "entities": [
            "not-a-dict",  # should be skipped
            {"handle": "ORG-EDGE", "roles": ["registrant"]},
        ]
    })

    # Org response that fails both JSON and XML parsing
    org_resp = FakeResponse(text="not valid json or xml")

    # Nets JSON with non-dict entries
    nets_resp = FakeResponse(json_data={
        "nets": {
            "netRef": [
                "not-a-dict",  # should be skipped
                {"@startAddress": "7.8.9.0", "@endAddress": "7.8.9.255"},
            ]
        }
    })

    def fake_get(url: str, timeout: int = 10):
        if url.endswith("/registry/ip/1.2.3.0"):
            return rdap_resp
        if url.endswith("/rest/org/ORG-EDGE"):
            return org_resp
        if url.endswith("/rest/org/ORG-EDGE/nets"):
            return nets_resp
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(crawler.session, "get", fake_get)

    result = transform(crawler, [rdap_resp], "test")
    assert "7.8.9.0/24" in result["ipv4"]
    assert result["source_updated_at"] is None  # org parsing failed
