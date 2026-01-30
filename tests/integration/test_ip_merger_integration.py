"""Integration tests for IPMerger with CloudIPRanges."""

import json
from pathlib import Path

import pytest

from src.cloud_ip_ranges import CloudIPRanges
from src.ip_merger import IPMerger


def test_cloud_ip_ranges_with_ipmerger_integration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test CloudIPRanges integration with IPMerger for merged outputs."""
    crawler = CloudIPRanges({"json", "csv"}, merge_all_providers=True)
    crawler.base_url = tmp_path

    # Mock source data with overlapping IPs from different providers
    mock_data = {
        "provider1": {
            "provider": "Provider 1",
            "provider_id": "provider1",
            "method": "published_list",
            "source": "https://example.com/provider1.json",
            "last_update": "2024-01-01T00:00:00",
            "ipv4": ["10.0.0.0/24", "192.168.1.0/24"],
            "ipv6": ["2001:db8::/32"],
        },
        "provider2": {
            "provider": "Provider 2",
            "provider_id": "provider2",
            "method": "published_list",
            "source": "https://example.com/provider2.json",
            "last_update": "2024-01-01T00:00:00",
            "ipv4": ["10.0.0.128/25", "203.0.113.0/24"],  # 10.0.0.128/25 overlaps with provider1
            "ipv6": ["2001:db8::/64"],  # Overlaps with provider1
        },
    }

    call_count = {"fetch_calls": 0}

    def mock_fetch_and_save(source_key: str) -> tuple[int, int]:
        call_count["fetch_calls"] += 1
        data = mock_data[source_key]
        if crawler.merge_all_providers:
            crawler.ip_merger.add_provider_data(data)
        return len(data["ipv4"]), len(data["ipv6"])

    monkeypatch.setattr(crawler, "_fetch_and_save", mock_fetch_and_save)
    monkeypatch.setattr(crawler, "sources", {"provider1": ["url1"], "provider2": ["url2"]})

    # Run the fetch
    result = crawler.fetch_all()

    assert result is True
    assert call_count["fetch_calls"] == 2
    assert crawler.ip_merger.has_data
    assert crawler.ip_merger.provider_count == 2

    # Check that merged outputs were created
    json_path = tmp_path / "all-providers.json"
    csv_path = tmp_path / "all-providers.csv"

    assert json_path.exists()
    assert csv_path.exists()

    # Check JSON content
    json_content = json.loads(json_path.read_text(encoding="utf-8"))
    assert json_content["provider"] == "All Providers"
    assert json_content["provider_count"] == 2
    assert "ip_providers" in json_content

    # Check CSV content
    csv_content = csv_path.read_text(encoding="utf-8")
    assert "Type,Address,Providers" in csv_content
    assert "provider1;provider2" in csv_content  # Should have merged providers


def test_ipmerger_real_world_overlapping_scenario(tmp_path: Path) -> None:
    """Test IPMerger with a realistic overlapping scenario."""
    merger = IPMerger()

    # Simulate real-world overlapping IP ranges from cloud providers
    providers_data = [
        {
            "provider_id": "aws",
            "provider": "Amazon Web Services",
            "ipv4": [
                "52.94.0.0/16",  # Large range
                "54.230.0.0/16",  # Another large range
            ],
            "ipv6": [
                "2600:1f14::/32",
            ],
        },
        {
            "provider_id": "cloudflare",
            "provider": "Cloudflare",
            "ipv4": [
                "52.94.5.0/24",  # Overlaps with AWS range
                "103.21.244.0/22",  # Non-overlapping
            ],
            "ipv6": [
                "2600:1f14::/36",  # Overlaps with AWS range
                "2400:cb00::/32",  # Non-overlapping
            ],
        },
        {
            "provider_id": "google",
            "provider": "Google Cloud",
            "ipv4": [
                "52.94.6.0/24",  # Also overlaps with AWS range
                "8.8.8.0/24",  # Non-overlapping
            ],
            "ipv6": [
                "2600:1f14::/40",  # Also overlaps with AWS range
                "2001:4860::/32",  # Non-overlapping
            ],
        },
    ]

    # Add all provider data
    for data in providers_data:
        merger.add_provider_data(data)

    # Get merged output
    merged_output = merger.get_merged_output()

    # Verify structure
    assert merged_output["provider_count"] == 3
    assert len(merged_output["providers"]) == 3
    assert "ip_providers" in merged_output

    # Check that overlapping networks have multiple providers
    ip_providers = merged_output["ip_providers"]

    # The large AWS range should have all three providers
    aws_large_range_providers = ip_providers.get("52.94.0.0/16", [])
    assert "aws" in aws_large_range_providers
    assert "cloudflare" in aws_large_range_providers
    assert "google" in aws_large_range_providers

    # Non-overlapping ranges should have single providers
    google_dns_providers = ip_providers.get("8.8.8.0/24", [])
    assert google_dns_providers == ["google"]

    # Check IPv6 overlapping
    aws_ipv6_providers = ip_providers.get("2600:1f14::/32", [])
    assert "aws" in aws_ipv6_providers
    assert "cloudflare" in aws_ipv6_providers
    assert "google" in aws_ipv6_providers


def test_ipmerger_output_formats_integration(tmp_path: Path) -> None:
    """Test that IPMerger works correctly with all output formats."""
    merger = IPMerger()

    # Add test data
    test_data = {
        "provider_id": "test_provider",
        "provider": "Test Provider",
        "ipv4": ["192.168.1.0/24", "10.0.0.0/8"],
        "ipv6": ["2001:db8::/32"],
    }

    merger.add_provider_data(test_data)

    # Test JSON output
    merged_output = merger.get_merged_output()

    # Verify JSON structure
    required_fields = ["provider", "generated_at", "provider_count", "providers", "ipv4", "ipv6", "ip_providers"]
    for field in required_fields:
        assert field in merged_output

    # Verify content
    assert merged_output["provider"] == "All Providers"
    assert merged_output["provider_count"] == 1
    assert len(merged_output["ipv4"]) == 2
    assert len(merged_output["ipv6"]) == 1
    assert len(merged_output["ip_providers"]) == 3  # 2 IPv4 + 1 IPv6

    # Test provider mapping
    for ip in merged_output["ipv4"]:
        providers = merged_output["ip_providers"][ip]
        assert providers == ["test_provider"]

    for ip in merged_output["ipv6"]:
        providers = merged_output["ip_providers"][ip]
        assert providers == ["test_provider"]


def test_cloud_ip_ranges_merger_disabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that CloudIPRanges works normally when merger is disabled."""
    crawler = CloudIPRanges({"json"}, merge_all_providers=False)
    crawler.base_url = tmp_path

    # Should have merger instance but not use it
    assert hasattr(crawler, "ip_merger")
    assert crawler.ip_merger is not None

    # Mock normal fetch
    def mock_fetch_and_save(source_key: str) -> tuple[int, int]:
        return (5, 2)  # Return some dummy counts

    monkeypatch.setattr(crawler, "_fetch_and_save", mock_fetch_and_save)
    monkeypatch.setattr(crawler, "sources", {"test": ["url"]})

    result = crawler.fetch_all()
    assert result is True

    # Merger should be empty since merge_all_providers is False
    assert not crawler.ip_merger.has_data
    assert crawler.ip_merger.provider_count == 0

    # Should not create merged outputs
    merged_json = tmp_path / "all-providers.json"
    assert not merged_json.exists()


def test_ipmerger_performance_with_large_dataset(tmp_path: Path) -> None:
    """Test IPMerger performance with a larger dataset."""
    merger = IPMerger()

    # Create a larger dataset
    large_dataset = []
    for i in range(100):  # 100 providers
        provider_data = {
            "provider_id": f"provider_{i}",
            "provider": f"Provider {i}",
            # Use even-numbered blocks only so collapse_addresses will not merge distinct entries.
            "ipv4": [f"10.{(i * 2) // 256}.{(i * 2) % 256}.0/24"],
            "ipv6": [f"2001:db8:{(i * 2):04x}::/64"],
        }
        large_dataset.append(provider_data)

    # Add all data
    import time

    start_time = time.time()

    for data in large_dataset:
        merger.add_provider_data(data)

    # Get merged output
    merged_output = merger.get_merged_output()

    end_time = time.time()
    processing_time = end_time - start_time

    # Should complete in reasonable time (less than 1 second for this dataset)
    assert processing_time < 1.0
    assert merger.provider_count == 100
    # Canonicalization keeps each /24 and /64 unique
    assert len(merged_output["ipv4"]) == 100
    assert len(merged_output["ipv6"]) == 100
    assert len(merged_output["ip_providers"]) == 200  # 100 IPv4 + 100 IPv6


def test_ipmerger_edge_case_empty_provider_data(tmp_path: Path) -> None:
    """Test IPMerger with provider data that has no IP ranges."""
    merger = IPMerger()

    # Add provider with no IPs
    empty_data = {
        "provider_id": "empty_provider",
        "provider": "Empty Provider",
        "ipv4": [],
        "ipv6": [],
    }

    merger.add_provider_data(empty_data)

    # Should still track the provider even with no IPs
    assert merger.has_data
    assert merger.provider_count == 1

    merged_output = merger.get_merged_output()

    # Should have provider info but no IP ranges
    assert merged_output["provider_count"] == 1
    assert len(merged_output["providers"]) == 1
    assert len(merged_output["ipv4"]) == 0
    assert len(merged_output["ipv6"]) == 0
    assert len(merged_output["ip_providers"]) == 0


def test_ipmerger_malformed_ip_addresses(tmp_path: Path) -> None:
    """Test IPMerger handling of malformed IP addresses."""
    merger = IPMerger()

    # Add data with various malformed IPs
    malformed_data = {
        "provider_id": "malformed_test",
        "ipv4": [
            "192.168.1.0/24",  # Valid
            "not.an.ip",  # Invalid
            "999.999.999.999/24",  # Invalid
            "192.168.1.0/33",  # Invalid prefix
            "10.0.0.0/8",  # Valid
        ],
        "ipv6": [
            "2001:db8::/32",  # Valid
            "not:ipv6",  # Invalid
            "2001:db8::/129",  # Invalid prefix
            "2001:db8::/64",  # Valid
        ],
    }

    merger.add_provider_data(malformed_data)

    # Should only process valid IPs
    assert merger.has_data
    assert merger.provider_count == 1

    merged_output = merger.get_merged_output()

    # Should only contain valid IPs
    assert "192.168.1.0/24" in merged_output["ipv4"]
    assert "10.0.0.0/8" in merged_output["ipv4"]
    assert "2001:db8::/32" in merged_output["ipv6"]

    # Should not contain malformed IPs
    assert len(merged_output["ipv4"]) == 2
    assert len(merged_output["ipv6"]) == 1  # Only the /32 network, /64 was merged


def test_cloud_ip_ranges_full_integration_workflow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test complete workflow with multiple providers and output formats."""
    crawler = CloudIPRanges({"json", "csv", "txt"}, merge_all_providers=True)
    crawler.base_url = tmp_path

    # Mock multiple providers with overlapping IPs
    providers_data = {
        "aws": {
            "provider": "Amazon Web Services",
            "provider_id": "aws",
            "method": "published_list",
            "source": "https://ip-ranges.amazonaws.com/ip-ranges.json",
            "last_update": "2024-01-01T00:00:00",
            "ipv4": ["52.94.0.0/16", "54.230.0.0/16"],
            "ipv6": ["2600:1f14::/32"],
        },
        "cloudflare": {
            "provider": "Cloudflare",
            "provider_id": "cloudflare",
            "method": "published_list",
            "source": "https://www.cloudflare.com/ips-v4",
            "last_update": "2024-01-01T00:00:00",
            "ipv4": ["52.94.5.0/24", "103.21.244.0/22"],  # Overlaps with AWS
            "ipv6": ["2600:1f14::/36", "2400:cb00::/32"],  # Overlaps with AWS
        },
        "google": {
            "provider": "Google Cloud",
            "provider_id": "google",
            "method": "published_list",
            "source": "https://www.gstatic.com/ipranges/cloud.json",
            "last_update": "2024-01-01T00:00:00",
            "ipv4": ["52.94.6.0/24", "8.8.8.0/24"],  # Overlaps with AWS
            "ipv6": ["2600:1f14::/40", "2001:4860::/32"],  # Overlaps with AWS
        },
    }

    call_count = {"fetch_calls": 0}

    def mock_fetch_and_save(source_key: str) -> tuple[int, int]:
        call_count["fetch_calls"] += 1
        data = providers_data[source_key]
        if crawler.merge_all_providers:
            crawler.ip_merger.add_provider_data(data)
        return len(data["ipv4"]), len(data["ipv6"])

    monkeypatch.setattr(crawler, "_fetch_and_save", mock_fetch_and_save)
    monkeypatch.setattr(crawler, "sources", providers_data)

    # Run the complete workflow
    result = crawler.fetch_all()

    assert result is True
    assert call_count["fetch_calls"] == 3
    assert crawler.ip_merger.has_data
    assert crawler.ip_merger.provider_count == 3

    # Check all output files were created
    json_path = tmp_path / "all-providers.json"
    csv_path = tmp_path / "all-providers.csv"
    txt_path = tmp_path / "all-providers.txt"

    assert json_path.exists()
    assert csv_path.exists()
    assert txt_path.exists()

    # Verify JSON content
    json_content = json.loads(json_path.read_text(encoding="utf-8"))
    assert json_content["provider"] == "All Providers"
    assert json_content["provider_count"] == 3
    assert len(json_content["providers"]) == 3
    assert "ip_providers" in json_content

    # Verify CSV content has providers column
    csv_content = csv_path.read_text(encoding="utf-8")
    assert "Type,Address,Providers" in csv_content
    assert "aws;cloudflare;google" in csv_content  # Should have merged providers

    # Verify TXT content
    txt_content = txt_path.read_text(encoding="utf-8")
    assert "# provider: All Providers" in txt_content
    assert "# providers_count: 3" in txt_content


def test_ipmerger_concurrent_provider_addition(tmp_path: Path) -> None:
    """Test IPMerger when providers are added concurrently (simulated)."""
    merger = IPMerger()

    # Simulate concurrent addition by adding data in rapid succession
    providers = []
    for i in range(20):
        provider_data = {
            "provider_id": f"concurrent_{i}",
            "provider": f"Concurrent Provider {i}",
            "ipv4": [f"172.16.{i * 2}.0/24"],
            "ipv6": [f"fd00:{(i * 2):04x}::/64"],
        }
        providers.append(provider_data)

    # Add all providers
    for data in providers:
        merger.add_provider_data(data)

    # Should handle all providers correctly
    assert merger.provider_count == 20
    assert merger.has_data

    merged_output = merger.get_merged_output()

    # Should have all provider data
    assert merged_output["provider_count"] == 20
    assert len(merged_output["providers"]) == 20
    assert len(merged_output["ipv4"]) == 20
    assert len(merged_output["ipv6"]) == 20
    assert len(merged_output["ip_providers"]) == 40


def test_ipmerger_reset_functionality(tmp_path: Path) -> None:
    """Test IPMerger reset functionality in integration context."""
    merger = IPMerger()

    # Add initial data
    data1 = {
        "provider_id": "initial",
        "ipv4": ["10.0.0.0/24"],
        "ipv6": ["2001:db8::/32"],
    }

    merger.add_provider_data(data1)
    assert merger.has_data
    assert merger.provider_count == 1

    # Reset
    merger.reset()
    assert not merger.has_data
    assert merger.provider_count == 0

    # Should be able to add new data after reset
    data2 = {
        "provider_id": "after_reset",
        "ipv4": ["192.168.1.0/24"],
        "ipv6": ["2001:db9::/32"],
    }

    merger.add_provider_data(data2)
    assert merger.has_data
    assert merger.provider_count == 1

    merged_output = merger.get_merged_output()
    assert merged_output["provider_count"] == 1
    assert len(merged_output["ipv4"]) == 1
    assert len(merged_output["ipv6"]) == 1


def test_ipmerger_boundary_conditions(tmp_path: Path) -> None:
    """Test IPMerger with various boundary conditions."""
    merger = IPMerger()

    # Test with minimum network sizes
    boundary_data = {
        "provider_id": "boundary_test",
        "ipv4": [
            "0.0.0.0/32",  # Single IPv4 address
            "255.255.255.255/32",  # Last IPv4 address
        ],
        "ipv6": [
            "::/128",  # Single IPv6 address
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",  # Last IPv6 address
        ],
    }

    merger.add_provider_data(boundary_data)

    assert merger.has_data
    merged_output = merger.get_merged_output()

    # Should handle boundary addresses correctly
    assert "0.0.0.0/32" in merged_output["ipv4"]
    assert "255.255.255.255/32" in merged_output["ipv4"]
    assert "::/128" in merged_output["ipv6"]
    assert "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128" in merged_output["ipv6"]


def test_cloud_ip_ranges_merger_disabled_integration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test CloudIPRanges integration when merger is disabled."""
    crawler = CloudIPRanges({"json", "csv"}, merge_all_providers=False)
    crawler.base_url = tmp_path

    # Mock provider data
    provider_data = {
        "provider_id": "test_provider",
        "ipv4": ["10.0.0.0/24"],
        "ipv6": ["2001:db8::/32"],
    }

    def mock_fetch_and_save(source_key: str) -> tuple[int, int]:
        # Should not call merger when disabled
        return len(provider_data["ipv4"]), len(provider_data["ipv6"])

    monkeypatch.setattr(crawler, "_fetch_and_save", mock_fetch_and_save)
    monkeypatch.setattr(crawler, "sources", {"test": ["url"]})

    result = crawler.fetch_all()

    assert result is True

    # Merger should be empty since merge_all_providers is False
    assert not crawler.ip_merger.has_data
    assert crawler.ip_merger.provider_count == 0

    # Should not create merged output files
    json_path = tmp_path / "all-providers.json"
    csv_path = tmp_path / "all-providers.csv"

    assert not json_path.exists()
    assert not csv_path.exists()


__all__ = [
    "test_cloud_ip_ranges_with_ipmerger_integration",
    "test_ipmerger_real_world_overlapping_scenario",
    "test_ipmerger_output_formats_integration",
    "test_cloud_ip_ranges_merger_disabled",
    "test_ipmerger_performance_with_large_dataset",
    "test_ipmerger_edge_case_empty_provider_data",
    "test_ipmerger_malformed_ip_addresses",
    "test_cloud_ip_ranges_full_integration_workflow",
    "test_ipmerger_concurrent_provider_addition",
    "test_ipmerger_reset_functionality",
    "test_ipmerger_boundary_conditions",
    "test_cloud_ip_ranges_merger_disabled_integration",
]
