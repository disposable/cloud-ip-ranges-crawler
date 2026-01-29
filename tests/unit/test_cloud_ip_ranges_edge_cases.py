"""Tests specifically designed to boost coverage to reach 85% threshold."""

from pathlib import Path

from src.cloud_ip_ranges import CloudIPRanges


def test_cloud_ip_ranges_initialization() -> None:
    """Test CloudIPRanges initialization with different parameters."""
    # Test with default parameters
    crawler1 = CloudIPRanges({"json"})
    assert crawler1.output_formats == {"json"}
    assert crawler1.only_if_changed is False
    assert crawler1.max_delta_ratio is None

    # Test with custom parameters
    crawler2 = CloudIPRanges({"json", "csv"}, only_if_changed=True, max_delta_ratio=0.1)
    assert crawler2.output_formats == {"json", "csv"}
    assert crawler2.only_if_changed is True
    assert crawler2.max_delta_ratio == 0.1


def test_cloud_ip_ranges_initialization_with_output_dir(tmp_path: Path) -> None:
    """Ensure custom output directories are honored and created."""
    target_dir = tmp_path / "outputs"
    crawler = CloudIPRanges({"json"}, output_dir=target_dir)

    assert crawler.base_url == target_dir
    assert target_dir.exists()


def test_transform_base_with_custom_source() -> None:
    """Test _transform_base with custom source URL."""
    crawler = CloudIPRanges({"json"})

    result = crawler._transform_base("test", ["https://custom.example.com/api"])

    assert result["method"] == "published_list"
    assert result["source"] == ["https://custom.example.com/api"]
    assert result["provider"] == "Test"  # Provider is capitalized
    assert result["provider_id"] == "test"
    assert "generated_at" in result
    assert "ipv4" in result
    assert "ipv6" in result


def test_save_details_files_with_no_details() -> None:
    """Test _save_details_files when no details are available."""
    crawler = CloudIPRanges({"json"})
    crawler.base_url = Path("/tmp")

    data = {"ipv4": ["8.8.8.0/24"], "ipv6": []}  # No details

    result = crawler._save_details_files(data, "test")
    assert result is False  # Should return False when no details


def test_xml_find_text_no_match() -> None:
    """Test _xml_find_text when no matching element is found."""
    from xml.etree.ElementTree import Element

    crawler = CloudIPRanges({"json"})

    root = Element("root")
    child = Element("child")
    child.text = "value"
    root.append(child)

    # Should return None for non-existent tag
    result = crawler._xml_find_text(root, "nonexistent")
    assert result is None


def test_enforce_max_delta_with_zero_old_count() -> None:
    """Test _enforce_max_delta when old count is zero."""
    crawler = CloudIPRanges({"json"})

    old_data = {"ipv4": [], "ipv6": []}  # Empty old data
    new_data = {"ipv4": ["8.8.8.0/24"], "ipv6": ["2606:4700::/32"]}  # New data has IPs

    # Should not raise when old count is zero (ratio would be infinite but not checked)
    crawler._enforce_max_delta(old_data, new_data, max_ratio=0.1, source_key="test")


def test_diff_summary_empty_data() -> None:
    """Test _diff_summary with empty data."""
    crawler = CloudIPRanges({"json"})

    old_data = {"ipv4": [], "ipv6": []}
    new_data = {"ipv4": [], "ipv6": []}

    summary = crawler._diff_summary(old_data, new_data)

    assert summary["ipv4"]["old"] == 0
    assert summary["ipv4"]["new"] == 0
    assert summary["ipv4"]["added"] == 0
    assert summary["ipv4"]["removed"] == 0
    assert summary["ipv6"]["old"] == 0
    assert summary["ipv6"]["new"] == 0
    assert summary["ipv6"]["added"] == 0
    assert summary["ipv6"]["removed"] == 0


def test_save_csv_details_with_empty_details() -> None:
    """Test _save_csv_details with empty details."""
    crawler = CloudIPRanges({"csv"})
    crawler.base_url = Path("/tmp")

    # Call with proper transformed_data dict structure
    transformed_data = {"details_ipv4": [], "details_ipv6": []}

    # Should handle empty details gracefully
    crawler._save_csv_details(transformed_data, "test")


def test_add_env_statistics_no_github_output() -> None:
    """Test add_env_statistics when GITHUB_OUTPUT is not set."""
    import os

    # Ensure GITHUB_OUTPUT is not set
    if "GITHUB_OUTPUT" in os.environ:
        del os.environ["GITHUB_OUTPUT"]

    crawler = CloudIPRanges({"json"})
    crawler.statistics = {"test": {"ipv4": 1, "ipv6": 2}}

    # Should not raise when GITHUB_OUTPUT is not set
    crawler.add_env_statistics()


def test_normalize_transformed_data_with_missing_keys() -> None:
    """Test _normalize_transformed_data with missing optional keys."""
    crawler = CloudIPRanges({"json"})

    data = {
        "ipv4": ["8.8.8.0/24"],
        "ipv6": ["2606:4700::/32"],
        # Missing details_ipv4 and details_ipv6 keys
    }

    result = crawler._normalize_transformed_data(data, "test")

    # Should handle missing keys gracefully
    assert "8.8.8.0/24" in result["ipv4"]
    assert "2606:4700::/32" in result["ipv6"]
    # Missing details keys should remain None (not added)
    assert result.get("details_ipv4") is None
    assert result.get("details_ipv6") is None
