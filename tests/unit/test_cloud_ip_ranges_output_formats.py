"""Additional tests for CloudIPRanges methods to reach coverage threshold."""

from pathlib import Path

from src.cloud_ip_ranges import CloudIPRanges


def test_save_result_with_txt_format(tmp_path: Path) -> None:
    """Test saving result in TXT format."""
    crawler = CloudIPRanges({"txt"})
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
        "ipv6": ["2606:4700::/32"],
    }

    crawler._save_result(data, "test")

    # Should create TXT file
    assert (tmp_path / "test.txt").exists()
    content = (tmp_path / "test.txt").read_text()
    assert "# provider: Test" in content
    assert "8.8.8.0/24" in content
    assert "2606:4700::/32" in content


def test_save_result_with_multiple_formats(tmp_path: Path) -> None:
    """Test saving result in multiple formats."""
    crawler = CloudIPRanges({"json", "csv", "txt"})
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
        "ipv6": ["2606:4700::/32"],
    }

    crawler._save_result(data, "test")

    # Should create all format files
    assert (tmp_path / "test.json").exists()
    assert (tmp_path / "test.csv").exists()
    assert (tmp_path / "test.txt").exists()


def test_normalize_transformed_data_with_mixed_validity() -> None:
    """Test _normalize_transformed_data with mix of valid and invalid IPs."""
    crawler = CloudIPRanges({"json"})

    data = {
        "ipv4": ["8.8.8.0/24", "invalid_ip", "192.168.1.0/24"],  # Mix of valid and invalid
        "ipv6": ["2606:4700::/32", "invalid_ipv6", "2001:db8::/32"],  # Mix of valid and invalid
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
    assert "2001:db8::/32" not in result["ipv6"]  # Documentation IP filtered out


def test_diff_summary_with_changes() -> None:
    """Test _diff_summary with changes between old and new data."""
    crawler = CloudIPRanges({"json"})

    old_data = {"ipv4": ["8.8.8.0/24"], "ipv6": ["2606:4700::/32"]}
    new_data = {"ipv4": ["8.8.8.0/24", "1.2.3.0/24"], "ipv6": ["2606:4700::/32", "2001:4860::/32"]}

    summary = crawler._diff_summary(old_data, new_data)

    assert summary["ipv4"]["old"] == 1
    assert summary["ipv4"]["new"] == 2
    assert summary["ipv4"]["added"] == 1
    assert summary["ipv4"]["removed"] == 0
    assert summary["ipv6"]["old"] == 1
    assert summary["ipv6"]["new"] == 2
    assert summary["ipv6"]["added"] == 1
    assert summary["ipv6"]["removed"] == 0


def test_xml_find_text_with_namespace() -> None:
    """Test _xml_find_text with XML namespaces."""
    from xml.etree.ElementTree import Element

    crawler = CloudIPRanges({"json"})

    # Create XML element with namespace
    root = Element("{http://example.com}root")
    child = Element("{http://example.com}child")
    child.text = "test_value"
    root.append(child)

    # Should find the text even with namespace
    result = crawler._xml_find_text(root, "child")
    assert result == "test_value"

    # Should return None for non-existent tag
    result = crawler._xml_find_text(root, "nonexistent")
    assert result is None
