"""Edge case tests to improve coverage."""

from pathlib import Path
import pytest

from src.cloud_ip_ranges import CloudIPRanges
from tests.unit.conftest import FakeResponse


def test_fetch_and_save_with_extra_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test _fetch_and_save with extra sources beyond the main sources dict."""
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"aws": ["https://example.com/test.json"]}

    def fake_get(url: str, timeout: int = 10):
        # Return proper AWS JSON structure
        return FakeResponse(
            json_data={
                "createDate": "2024-01-01T00:00:00Z",
                "prefixes": [
                    {"ip_prefix": "1.2.3.0/24", "region": "us-east-1", "service": "EC2"},
                    {"ipv6_prefix": "2606:4700::/32", "region": "us-east-1", "service": "EC2"},
                ],
            }
        )

    monkeypatch.setattr(crawler.session, "get", fake_get)

    # This should work even if the source isn't in the predefined sources
    res = crawler._fetch_and_save("aws")
    assert res is not None
    assert isinstance(res, tuple)


def test_save_result_with_details_and_csv(tmp_path: Path) -> None:
    """Test saving result with details files and CSV format."""
    crawler = CloudIPRanges({"json", "csv"})
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
        "details_ipv4": [{"address": "8.8.8.0/24", "service": "test"}],
        "details_ipv6": [{"address": "2001:db8::/32", "service": "test"}],
    }

    crawler._save_result(data, "test")

    # Should create main file and details files in both formats
    assert (tmp_path / "test.json").exists()
    assert (tmp_path / "test.csv").exists()
    assert (tmp_path / "test-details.json").exists()
    assert (tmp_path / "test-details.csv").exists()


def test_transform_base_with_source_url() -> None:
    """Test _transform_base with custom source URL."""
    crawler = CloudIPRanges({"json"})

    result = crawler._transform_base("test", ["https://custom.example.com/api"])

    assert result["method"] == "published_list"
    assert result["source"] == ["https://custom.example.com/api"]


def test_normalize_transformed_data_with_empty_details() -> None:
    """Test _normalize_transformed_data with empty details lists."""
    crawler = CloudIPRanges({"json"})

    data = {
        "ipv4": ["8.8.8.0/24"],
        "ipv6": ["2606:4700::/32"],  # Use public IPv6
        "details_ipv4": [],  # Empty list
        "details_ipv6": [],  # Empty list
    }

    result = crawler._normalize_transformed_data(data, "test")

    # Should handle empty details gracefully
    assert "8.8.8.0/24" in result["ipv4"]
    assert "2606:4700::/32" in result["ipv6"]
    assert result.get("details_ipv4") == []
    assert result.get("details_ipv6") == []


def test_save_txt_format(tmp_path: Path) -> None:
    """Test saving data in TXT format."""
    crawler = CloudIPRanges({"txt"})
    crawler.base_url = tmp_path

    data = {
        "provider": "Test Provider",
        "provider_id": "test",
        "method": "published_list",
        "coverage_notes": "",
        "generated_at": "2024-01-01T00:00:00",
        "source_updated_at": "2024-01-01T00:00:00",
        "source": ["https://example.com/test"],
        "last_update": "2024-01-01T00:00:00",
        "ipv4": ["8.8.8.0/24", "8.8.9.0/24"],
        "ipv6": ["2606:4700::/32"],  # Use public IPv6
    }

    crawler._save_result(data, "test")

    # Should create TXT file
    assert (tmp_path / "test.txt").exists()
    content = (tmp_path / "test.txt").read_text()
    assert "# provider: Test Provider" in content
    assert "8.8.8.0/24" in content
    assert "2606:4700::/32" in content


def test_diff_summary_with_no_changes() -> None:
    """Test _diff_summary with identical old and new data."""
    crawler = CloudIPRanges({"json"})

    old_data = {"ipv4": ["8.8.8.0/24"], "ipv6": ["2606:4700::/32"]}
    new_data = {"ipv4": ["8.8.8.0/24"], "ipv6": ["2606:4700::/32"]}

    summary = crawler._diff_summary(old_data, new_data)

    assert summary["ipv4"]["old"] == 1
    assert summary["ipv4"]["new"] == 1
    assert summary["ipv4"]["added"] == 0
    assert summary["ipv4"]["removed"] == 0
    assert summary["ipv6"]["old"] == 1
    assert summary["ipv6"]["new"] == 1
    assert summary["ipv6"]["added"] == 0
    assert summary["ipv6"]["removed"] == 0
