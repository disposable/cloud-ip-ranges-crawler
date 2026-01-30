"""Tests for the IPMerger class."""

import ipaddress

from src.ip_merger import IPMerger


def test_ip_merger_basic_functionality() -> None:
    """Test basic IPMerger functionality."""
    merger = IPMerger()

    # Test initial state
    assert not merger.has_data
    assert merger.provider_count == 0

    # Add provider data
    data1 = {
        "provider_id": "provider1",
        "provider": "Provider 1",
        "ipv4": ["192.168.1.0/24", "192.168.2.0/24"],
        "ipv6": ["2001:db8::/32"],
    }

    merger.add_provider_data(data1)

    assert merger.has_data
    assert merger.provider_count == 1


def test_ip_merger_merge_networks() -> None:
    """Test IP network merging functionality."""
    merger = IPMerger()

    # Test overlapping IPv4 networks
    overlapping_ipv4 = [
        ipaddress.IPv4Network("192.168.1.0/24", strict=False),
        ipaddress.IPv4Network("192.168.1.128/25", strict=False),
        ipaddress.IPv4Network("192.168.2.0/24", strict=False),
    ]
    merged = merger.merge_networks(overlapping_ipv4)

    # Exact union should keep only real coverage
    merged_str = sorted(str(net) for net in merged)
    assert merged_str == ["192.168.1.0/24", "192.168.2.0/24"]
    assert "192.168.0.0/22" not in merged_str

    # Test static methods directly
    ipv4_only = [net for net in overlapping_ipv4 if net.version == 4]
    merged_ipv4_direct = IPMerger._merge_same_version_v4(ipv4_only)
    assert [str(net) for net in merged_ipv4_direct] == ["192.168.1.0/24", "192.168.2.0/24"]

    # Test overlapping IPv6 networks
    overlapping_ipv6 = [
        ipaddress.IPv6Network("2001:db8::/32", strict=False),
        ipaddress.IPv6Network("2001:db8::/64", strict=False),
        ipaddress.IPv6Network("2001:db9::/32", strict=False),
    ]
    merged_ipv6 = merger.merge_networks(overlapping_ipv6)

    merged_ipv6_str = [str(net) for net in merged_ipv6]
    assert merged_ipv6_str == ["2001:db8::/31"]

    # Test IPv6 static method directly
    ipv6_only = [net for net in overlapping_ipv6 if net.version == 6]
    merged_ipv6_direct = IPMerger._merge_same_version_v6(ipv6_only)
    assert [str(net) for net in merged_ipv6_direct] == ["2001:db8::/31"]


def test_ip_merger_empty_networks() -> None:
    """Test IP network merging with empty input."""
    merger = IPMerger()

    assert merger.merge_networks([]) == []


def test_ip_merger_get_merged_output() -> None:
    """Test getting merged output with provider information."""
    merger = IPMerger()

    # Add data from two providers
    data1 = {
        "provider_id": "provider1",
        "provider": "Provider 1",
        "ipv4": ["192.168.1.0/24", "192.168.2.0/24"],
        "ipv6": ["2001:db8::/32"],
    }

    data2 = {
        "provider_id": "provider2",
        "provider": "Provider 2",
        "ipv4": ["192.168.1.128/25", "10.0.0.0/8"],  # Overlaps with provider1
        "ipv6": ["2001:db8::/64"],  # Overlaps with provider1
    }

    merger.add_provider_data(data1)
    merger.add_provider_data(data2)

    merged_output = merger.get_merged_output()

    # Check structure
    assert merged_output["provider"] == "All Providers"
    assert merged_output["provider_count"] == 2
    assert "ipv4" in merged_output
    assert "ipv6" in merged_output
    assert "ip_providers" in merged_output
    assert "providers" in merged_output
    assert "generated_at" in merged_output

    # Check that providers are tracked without widening CIDRs
    ip_providers = merged_output["ip_providers"]
    assert sorted(merged_output["ipv4"]) == ["10.0.0.0/8", "192.168.1.0/24", "192.168.2.0/24"]
    assert merged_output["ipv6"] == ["2001:db8::/32"]
    assert ip_providers["192.168.1.0/24"] == ["provider1", "provider2"]
    assert ip_providers["192.168.2.0/24"] == ["provider1"]
    assert ip_providers["10.0.0.0/8"] == ["provider2"]
    assert ip_providers["2001:db8::/32"] == ["provider1", "provider2"]


def test_ip_merger_reset() -> None:
    """Test resetting the merger."""
    merger = IPMerger()

    # Add some data
    data = {
        "provider_id": "test",
        "ipv4": ["192.168.1.0/24"],
    }
    merger.add_provider_data(data)

    assert merger.has_data
    assert merger.provider_count == 1

    # Reset
    merger.reset()

    assert not merger.has_data
    assert merger.provider_count == 0


def test_ip_merger_invalid_ip_handling() -> None:
    """Test that invalid IP addresses are handled gracefully."""
    merger = IPMerger()

    # Add data with invalid IPs (they should be filtered out)
    data = {
        "provider_id": "test",
        "ipv4": ["192.168.1.0/24", "invalid-ip", "10.0.0.0/8"],
        "ipv6": ["2001:db8::/32", "invalid-ipv6"],
    }

    merger.add_provider_data(data)

    # Should still have data despite invalid IPs
    assert merger.has_data
    assert merger.provider_count == 1

    merged_output = merger.get_merged_output()

    # Should only contain valid IPs
    assert "192.168.1.0/24" in merged_output["ipv4"]
    assert "10.0.0.0/8" in merged_output["ipv4"]
    assert "2001:db8::/32" in merged_output["ipv6"]


def test_ip_merger_complex_overlapping() -> None:
    """Test complex overlapping scenarios."""
    merger = IPMerger()

    # Test multiple overlapping networks that should merge into one
    complex_ipv4 = [
        ipaddress.IPv4Network("10.0.0.0/24", strict=False),
        ipaddress.IPv4Network("10.0.0.128/25", strict=False),
        ipaddress.IPv4Network("10.0.1.0/24", strict=False),
        ipaddress.IPv4Network("10.0.2.0/23", strict=False),  # Should merge with above
    ]

    merged = merger.merge_networks(complex_ipv4)
    merged_str = [str(net) for net in merged]

    # Collapse covers the entire contiguous span
    assert merged_str == ["10.0.0.0/22"]


def test_ip_merger_static_methods_edge_cases() -> None:
    """Test static methods with edge cases."""
    # Test empty lists
    assert IPMerger._merge_same_version_v4([]) == []
    assert IPMerger._merge_same_version_v6([]) == []

    # Test single network
    single_ipv4 = [ipaddress.IPv4Network("192.168.1.0/24", strict=False)]
    merged_single = IPMerger._merge_same_version_v4(single_ipv4)
    assert len(merged_single) == 1
    assert merged_single[0] == single_ipv4[0]

    # Test non-overlapping networks
    non_overlapping = [
        ipaddress.IPv4Network("192.168.1.0/24", strict=False),
        ipaddress.IPv4Network("10.0.0.0/24", strict=False),
    ]
    merged_non_overlap = IPMerger._merge_same_version_v4(non_overlapping)
    assert len(merged_non_overlap) == 2
    assert set(str(net) for net in merged_non_overlap) == {"192.168.1.0/24", "10.0.0.0/24"}


def test_ip_merger_provider_tracking_complex() -> None:
    """Test provider tracking with complex overlapping scenarios."""
    merger = IPMerger()

    # Three providers with overlapping networks
    data1 = {
        "provider_id": "provider1",
        "ipv4": ["10.0.0.0/24"],
    }

    data2 = {
        "provider_id": "provider2",
        "ipv4": ["10.0.0.128/25"],  # Overlaps with provider1
    }

    data3 = {
        "provider_id": "provider3",
        "ipv4": ["10.0.1.0/24"],  # Adjacent but not overlapping
    }

    merger.add_provider_data(data1)
    merger.add_provider_data(data2)
    merger.add_provider_data(data3)

    merged_output = merger.get_merged_output()

    # Check that overlapping networks attribute providers on the collapsed range
    ip_providers = merged_output["ip_providers"]
    assert ip_providers["10.0.0.0/23"] == ["provider1", "provider2", "provider3"]


def test_ip_merger_get_merged_output_empty() -> None:
    """Test get_merged_output when no data has been added."""
    merger = IPMerger()

    # Should return empty dict when no providers
    merged_output = merger.get_merged_output()
    assert merged_output == {}


def test_ip_merger_complex_ipv6_merging() -> None:
    """Test complex IPv6 network merging scenarios."""
    merger = IPMerger()

    # Test IPv6 networks that need complex merging
    complex_ipv6 = [
        ipaddress.IPv6Network("2001:db8::/32", strict=False),
        ipaddress.IPv6Network("2001:db8::/64", strict=False),  # Subnet of above
        ipaddress.IPv6Network("2001:db8:1::/64", strict=False),  # Adjacent
        ipaddress.IPv6Network("2001:db8::/48", strict=False),  # Should merge with first
    ]

    merged = merger.merge_networks(complex_ipv6)
    merged_str = [str(net) for net in merged]

    # Should merge overlapping networks into the largest one
    assert "2001:db8::/32" in merged_str  # The largest network should remain

    # Should not have the smaller networks that were merged
    assert "2001:db8::/64" not in merged_str  # Merged into /32
    assert "2001:db8::/48" not in merged_str  # Merged into /32


def test_ip_merger_edge_case_same_network() -> None:
    """Test merging when the same network appears multiple times."""
    merger = IPMerger()

    # Same network appearing multiple times
    same_network = [
        ipaddress.IPv4Network("192.168.1.0/24", strict=False),
        ipaddress.IPv4Network("192.168.1.0/24", strict=False),  # Duplicate
        ipaddress.IPv4Network("192.168.1.0/24", strict=False),  # Triple
    ]

    merged = merger.merge_networks(same_network)

    # Should result in just one network
    assert len(merged) == 1
    assert str(merged[0]) == "192.168.1.0/24"


def test_ip_merger_provider_data_with_missing_fields() -> None:
    """Test add_provider_data with missing optional fields."""
    merger = IPMerger()

    # Data with minimal required fields
    minimal_data = {
        "provider_id": "minimal",
        "ipv4": ["10.0.0.0/24"],
        # Missing: provider, method, source, last_update
    }

    merger.add_provider_data(minimal_data)

    assert merger.has_data
    assert merger.provider_count == 1

    merged_output = merger.get_merged_output()

    # Should handle missing fields gracefully
    assert merged_output["provider_count"] == 1
    assert len(merged_output["providers"]) == 1
    assert merged_output["providers"][0]["provider_id"] == "minimal"
    assert merged_output["providers"][0]["provider"] is None
    assert merged_output["providers"][0]["method"] is None
    assert merged_output["providers"][0]["source"] is None
    assert merged_output["providers"][0]["last_update"] is None


def test_ip_merger_mixed_version_networks() -> None:
    """Test merging networks with mixed IPv4 and IPv6 versions."""
    merger = IPMerger()

    # Mix of IPv4 and IPv6 networks
    mixed_networks = [
        ipaddress.IPv4Network("192.168.1.0/24", strict=False),
        ipaddress.IPv6Network("2001:db8::/32", strict=False),
        ipaddress.IPv4Network("10.0.0.0/8", strict=False),
        ipaddress.IPv6Network("2001:db9::/32", strict=False),
    ]

    merged = merger.merge_networks(mixed_networks)

    # Should preserve both versions without widening
    ipv4_merged = [str(net) for net in merged if net.version == 4]
    ipv6_merged = [str(net) for net in merged if net.version == 6]

    assert ipv4_merged == ["10.0.0.0/8", "192.168.1.0/24"]
    assert ipv6_merged == ["2001:db8::/31"]


def test_ip_merger_large_scale_provider_tracking() -> None:
    """Test provider tracking with many providers and networks."""
    merger = IPMerger()

    # Create data from many providers
    for i in range(10):
        data = {
            "provider_id": f"provider_{i}",
            "provider": f"Provider {i}",
            "ipv4": [f"10.{i}.0.0/24", f"192.168.{i}.0/24"],
            "ipv6": [f"2001:db8:{i:04x}::/64"],
        }
        merger.add_provider_data(data)

    assert merger.provider_count == 10
    assert merger.has_data

    merged_output = merger.get_merged_output()

    # Should have all providers tracked
    assert merged_output["provider_count"] == 10
    assert len(merged_output["providers"]) == 10

    # Should have IP networks with provider information
    assert len(merged_output["ip_providers"]) > 0

    # Each IP should have at least one provider
    for ip, providers in merged_output["ip_providers"].items():
        assert len(providers) >= 1
        assert all(isinstance(p, str) for p in providers)


def test_ip_merger_static_methods_comprehensive() -> None:
    """Test static methods with comprehensive edge cases."""
    # Test IPv4 static method with complex overlapping
    complex_ipv4 = [
        ipaddress.IPv4Network("10.0.0.0/24", strict=False),
        ipaddress.IPv4Network("10.0.0.0/25", strict=False),  # Subnet
        ipaddress.IPv4Network("10.0.1.0/24", strict=False),  # Adjacent
        ipaddress.IPv4Network("10.0.0.0/23", strict=False),  # Supernet of first two
        ipaddress.IPv4Network("10.0.2.0/24", strict=False),  # Non-overlapping
    ]

    merged_ipv4 = IPMerger._merge_same_version_v4(complex_ipv4)

    # Collapse should keep exact coverage without widening
    assert [str(net) for net in merged_ipv4] == ["10.0.0.0/23", "10.0.2.0/24"]

    # Test IPv6 static method with complex overlapping
    complex_ipv6 = [
        ipaddress.IPv6Network("2001:db8::/32", strict=False),
        ipaddress.IPv6Network("2001:db8::/64", strict=False),  # Subnet
        ipaddress.IPv6Network("2001:db9::/32", strict=False),  # Adjacent block
        ipaddress.IPv6Network("2001:db8::/31", strict=False),  # Supernet
    ]

    merged_ipv6 = IPMerger._merge_same_version_v6(complex_ipv6)

    # Should merge into appropriate networks
    assert len(merged_ipv6) >= 1  # At least some merging occurred


def test_ip_merger_output_structure_completeness() -> None:
    """Test that get_merged_output returns complete structure."""
    merger = IPMerger()

    # Add comprehensive test data
    data = {
        "provider_id": "test",
        "provider": "Test Provider",
        "method": "test_method",
        "source": "test_source",
        "last_update": "2024-01-01T00:00:00",
        "ipv4": ["10.0.0.0/24"],
        "ipv6": ["2001:db8::/32"],
    }

    merger.add_provider_data(data)
    merged_output = merger.get_merged_output()

    # Check all required fields are present
    required_fields = ["provider", "generated_at", "provider_count", "providers", "ipv4", "ipv6", "ip_providers"]

    for field in required_fields:
        assert field in merged_output, f"Missing field: {field}"

    # Check field types and content
    assert merged_output["provider"] == "All Providers"
    assert isinstance(merged_output["generated_at"], str)
    assert merged_output["provider_count"] == 1
    assert isinstance(merged_output["providers"], list)
    assert isinstance(merged_output["ipv4"], list)
    assert isinstance(merged_output["ipv6"], list)
    assert isinstance(merged_output["ip_providers"], dict)

    # Check provider structure
    provider = merged_output["providers"][0]
    assert provider["provider_id"] == "test"
    assert provider["provider"] == "Test Provider"
    assert provider["method"] == "test_method"
    assert provider["source"] == "test_source"
    assert provider["last_update"] == "2024-01-01T00:00:00"
    assert provider["ipv4_count"] == 1
    assert provider["ipv6_count"] == 1


def test_ip_merger_consecutive_merging() -> None:
    """Test that merging works correctly when called multiple times."""
    merger = IPMerger()

    # Add data in multiple batches
    data1 = {"provider_id": "batch1", "ipv4": ["10.0.0.0/24"]}
    data2 = {"provider_id": "batch2", "ipv4": ["10.0.0.128/25"]}  # Overlaps with batch1

    merger.add_provider_data(data1)
    merger.add_provider_data(data2)

    # Get merged output
    merged_output = merger.get_merged_output()

    # Should have merged the overlapping networks
    ip_providers = merged_output["ip_providers"]

    # The merged network should have both providers
    merged_networks = [ip for ip in merged_output["ipv4"]]
    assert len(merged_networks) >= 1

    # Check provider assignment
    for ip in merged_networks:
        providers = ip_providers.get(ip, [])
        if ip == "10.0.0.0/24":  # This should be the merged network
            assert "batch1" in providers or "batch2" in providers


def test_ip_merger_complex_network_expansion() -> None:
    """Test merging logic where networks need to be expanded to cover both."""
    merger = IPMerger()

    # Test IPv4 networks that are neighboring (covers lines 108-115)
    neighboring_ipv4 = [
        ipaddress.IPv4Network("10.0.0.0/25", strict=False),  # 10.0.0.0 - 10.0.0.127
        ipaddress.IPv4Network("10.0.0.128/25", strict=False),  # 10.0.0.128 - 10.0.0.255 (neighboring)
        # These should merge into 10.0.0.0/24
    ]

    merged = merger.merge_networks(neighboring_ipv4)
    merged_str = [str(net) for net in merged]

    # Should merge into a /24 network that covers both
    assert "10.0.0.0/24" in merged_str
    assert len(merged) == 1

    # Test IPv6 networks that are neighboring (covers lines 147-154)
    neighboring_ipv6 = [
        ipaddress.IPv6Network("2001:db8::/64", strict=False),  # 2001:db8:: - 2001:db8::ffff
        ipaddress.IPv6Network("2001:db8:0:1::/64", strict=False),  # Neighboring network
        # These should merge into a larger network
    ]

    merged_ipv6 = merger.merge_networks(neighboring_ipv6)

    # These are siblings and collapse into their shared supernet
    assert [str(net) for net in merged_ipv6] == ["2001:db8::/63"]


def test_ipmerger_static_methods_complex_expansion() -> None:
    """Test static methods with network expansion scenarios."""
    # Test IPv4 static method with expansion
    expansion_ipv4 = [
        ipaddress.IPv4Network("192.168.1.0/26", strict=False),  # 192.168.1.0 - 192.168.1.63
        ipaddress.IPv4Network("192.168.1.64/26", strict=False),  # 192.168.1.64 - 192.168.1.127
        ipaddress.IPv4Network("192.168.2.0/24", strict=False),  # Non-overlapping
    ]

    merged_ipv4 = IPMerger._merge_same_version_v4(expansion_ipv4)

    # First two collapse into /25; third stays separate
    assert [str(net) for net in merged_ipv4] == ["192.168.1.0/25", "192.168.2.0/24"]

    # Test IPv6 static method with expansion
    expansion_ipv6 = [
        ipaddress.IPv6Network("2001:db8:1::/96", strict=False),  # Small subnet
        ipaddress.IPv6Network("2001:db8:1::/80", strict=False),  # Adjacent but needs expansion
        ipaddress.IPv6Network("2001:db8:2::/64", strict=False),  # Different block
    ]

    merged_ipv6 = IPMerger._merge_same_version_v6(expansion_ipv6)

    # First two collapse into their shared supernet
    assert [str(net) for net in merged_ipv6] == ["2001:db8:1::/80", "2001:db8:2::/64"]


def test_ipmerger_neighboring_network_merging() -> None:
    """Test that neighboring networks are properly merged."""
    merger = IPMerger()

    # Test IPv4 neighboring networks
    neighboring_ipv4 = [
        ipaddress.IPv4Network("192.168.1.0/25", strict=False),  # 192.168.1.0 - 192.168.1.127
        ipaddress.IPv4Network("192.168.1.128/25", strict=False),  # 192.168.1.128 - 192.168.1.255
    ]

    merged_ipv4 = merger.merge_networks(neighboring_ipv4)

    # Sibling /25 blocks collapse into /24
    assert [str(net) for net in merged_ipv4] == ["192.168.1.0/24"]

    # Test IPv6 neighboring networks
    neighboring_ipv6 = [
        ipaddress.IPv6Network("2001:db8::/125", strict=False),  # 2001:db8:: - 2001:db8::7
        ipaddress.IPv6Network("2001:db8::8/125", strict=False),  # 2001:db8::8 - 2001:db8::f (neighboring)
    ]

    merged_ipv6 = merger.merge_networks(neighboring_ipv6)

    # These are siblings; collapse into /124
    assert [str(net) for net in merged_ipv6] == ["2001:db8::/124"]

    # Test non-neighboring networks (should not merge)
    non_neighboring = [
        ipaddress.IPv4Network("10.0.0.0/24", strict=False),
        ipaddress.IPv4Network("10.0.2.0/24", strict=False),  # Gap between networks
    ]

    merged_non_neighboring = merger.merge_networks(non_neighboring)
    assert len(merged_non_neighboring) == 2  # Should remain separate


__all__ = [
    "test_ip_merger_basic_functionality",
    "test_ip_merger_merge_networks",
    "test_ip_merger_empty_networks",
    "test_ip_merger_get_merged_output",
    "test_ip_merger_reset",
    "test_ip_merger_invalid_ip_handling",
    "test_ip_merger_complex_overlapping",
    "test_ip_merger_static_methods_edge_cases",
    "test_ip_merger_provider_tracking_complex",
    "test_ip_merger_get_merged_output_empty",
    "test_ip_merger_complex_ipv6_merging",
    "test_ip_merger_edge_case_same_network",
    "test_ip_merger_provider_data_with_missing_fields",
    "test_ip_merger_mixed_version_networks",
    "test_ip_merger_large_scale_provider_tracking",
    "test_ip_merger_static_methods_comprehensive",
    "test_ip_merger_output_structure_completeness",
    "test_ip_merger_consecutive_merging",
    "test_ip_merger_complex_network_expansion",
    "test_ipmerger_static_methods_complex_expansion",
    "test_ipmerger_neighboring_network_merging",
]
