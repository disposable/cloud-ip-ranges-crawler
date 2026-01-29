"""Additional tests to improve coverage for CloudIPRanges class."""

import os
import pytest
from pathlib import Path

from src.cloud_ip_ranges import CloudIPRanges


def test_save_result_with_only_if_changed_no_existing_file(tmp_path: Path) -> None:
    """Test saving with only_if_changed when no existing file exists."""
    crawler = CloudIPRanges({"json"}, only_if_changed=True)
    crawler.base_url = tmp_path

    data = {
        "provider": "Test",
        "provider_id": "test",
        "method": "published_list",
        "coverage_notes": "",
        "generated_at": "2024-01-01T00:00:00",
        "source_updated_at": "2024-01-01T00:00:00",
        "source": "https://example.com/test",
        "last_update": "2024-01-01T00:00:00",
        "ipv4": ["8.8.8.0/24"],
        "ipv6": ["2001:db8::/32"],
    }

    # Should save file when no existing file
    crawler._save_result(data, "test")
    assert (tmp_path / "test.json").exists()


def test_save_result_with_only_if_changed_unchanged(tmp_path: Path) -> None:
    """Test saving with only_if_changed when content is unchanged."""
    crawler = CloudIPRanges({"json"}, only_if_changed=True)
    crawler.base_url = tmp_path

    data = {
        "provider": "Test",
        "provider_id": "test",
        "method": "published_list",
        "coverage_notes": "",
        "generated_at": "2024-01-01T00:00:00",
        "source_updated_at": "2024-01-01T00:00:00",
        "source": "https://example.com/test",
        "last_update": "2024-01-01T00:00:00",
        "ipv4": ["8.8.8.0/24"],
        "ipv6": ["2001:db8::/32"],
    }

    # Create existing file
    existing_file = tmp_path / "test.json"
    existing_file.write_text('{"provider": "Test", "ipv4": ["8.8.8.0/24"], "ipv6": ["2001:db8::/32"]}')

    # Mock file modification time to be recent
    import time

    current_time = time.time()
    os.utime(existing_file, (current_time, current_time))

    # Should not save file when content is unchanged
    crawler._save_result(data, "test")
    # File should still exist but content unchanged
    assert existing_file.exists()
    content = existing_file.read_text()
    assert '"provider": "Test"' in content


def test_audit_transformed_data_passes(tmp_path: Path) -> None:
    """Test audit passes for valid data."""
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path

    data = {
        "provider": "Test",
        "provider_id": "test",
        "method": "published_list",
        "coverage_notes": "",
        "generated_at": "2024-01-01T00:00:00",
        "source_updated_at": "2024-01-01T00:00:00",
        "source": "https://example.com/test",
        "last_update": "2024-01-01T00:00:00",
        "ipv4": ["8.8.8.0/24"],
        "ipv6": ["2001:db8::/32"],
    }

    # Should not raise any exception
    crawler._audit_transformed_data(data, "test")


def test_audit_transformed_data_fails_on_private_ip(tmp_path: Path) -> None:
    """Test audit fails for default route IPs."""
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path

    data = {
        "provider": "Test",
        "provider_id": "test",
        "method": "published_list",
        "coverage_notes": "",
        "generated_at": "2024-01-01T00:00:00",
        "source_updated_at": "2024-01-01T00:00:00",
        "source": "https://example.com/test",
        "last_update": "2024-01-01T00:00:00",
        "ipv4": ["0.0.0.0/0"],  # Default route - this is what audit checks for
        "ipv6": [],
    }

    with pytest.raises(RuntimeError, match="contains default route"):
        crawler._audit_transformed_data(data, "test")


def test_xml_find_text_function() -> None:
    """Test the _xml_find_text helper function."""
    from xml.etree.ElementTree import Element

    crawler = CloudIPRanges({"json"})

    # Create XML element with nested namespace
    root = Element("root")
    child = Element("{http://example.com}child")
    child.text = "test_value"
    root.append(child)

    # Should find the text
    result = crawler._xml_find_text(root, "child")
    assert result == "test_value"

    # Should return None for non-existent tag
    result = crawler._xml_find_text(root, "nonexistent")
    assert result is None


def test_transform_base_with_asn_source() -> None:
    """Test _transform_base with ASN source."""
    crawler = CloudIPRanges({"json"})

    result = crawler._transform_base("test", ["AS12345"])

    assert result["method"] == "asn_lookup"
    assert result["source"] == ["AS12345"]


def test_normalize_transformed_data_with_invalid_ips() -> None:
    """Test _normalize_transformed_data with invalid IPs."""
    crawler = CloudIPRanges({"json"})

    data = {
        "ipv4": ["8.8.8.0/24", "invalid_ip", "192.168.1.0/24"],  # Mix of valid and invalid
        "ipv6": ["2606:4700::/32", "invalid_ipv6"],  # Valid public IPv6 + invalid
        "details_ipv4": [{"address": "8.8.8.0/24", "service": "test"}],
        "details_ipv6": [{"address": "2606:4700::/32", "service": "test"}],
    }

    result = crawler._normalize_transformed_data(data, "test")

    # Should only contain valid, public IPs
    assert "8.8.8.0/24" in result["ipv4"]
    assert "invalid_ip" not in result["ipv4"]
    assert "192.168.1.0/24" not in result["ipv4"]  # Private IP filtered out
    assert "2606:4700::/32" in result["ipv6"]
    assert "invalid_ipv6" not in result["ipv6"]
