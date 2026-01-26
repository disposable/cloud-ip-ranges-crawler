"""Integration tests for seed CIDR/RDAP functionality."""

import pytest
import requests
import tempfile
from pathlib import Path

from src.cloud_ip_ranges import CloudIPRanges
from src.sources.seed_cidr import fetch_and_save_seed_cidr_source
from src.transforms.seed_rdap_registry import transform


@pytest.mark.integration
def test_vercel_seed_cidr_workflow(skip_if_no_internet, rate_limit_delay):
    """Test complete seed CIDR workflow for Vercel."""
    cipr = CloudIPRanges({"json"})

    # Test Vercel seed CIDRs
    provider = "vercel"
    seeds = cipr.sources[provider]  # ["76.76.21.0/24", "198.169.1.0/24", "155.121.0.0/16"]

    # Fetch and transform using seed CIDR source
    result = fetch_and_save_seed_cidr_source(cipr, provider, seeds)

    # Validate the result
    assert result["provider"] == "Vercel"
    assert result["method"] == "rdap_registry"
    assert "coverage_notes" in result
    assert len(result["ipv4"]) > 0 or len(result["ipv6"]) > 0

    # Validate IP ranges format
    import ipaddress
    for ip_range in result["ipv4"]:
        ipaddress.ip_network(ip_range, strict=False)

    for ip_range in result["ipv6"]:
        ipaddress.ip_network(ip_range, strict=False)


@pytest.mark.integration
def test_rdap_registry_lookups(skip_if_no_internet, rate_limit_delay):
    """Test direct RDAP registry lookups."""
    # Test with a known IP from Vercel's range
    test_ip = "76.76.21.1"
    rdap_url = f"https://rdap.arin.net/registry/ip/{test_ip}"

    response = requests.get(rdap_url, timeout=10)
    response.raise_for_status()

    # Validate RDAP response structure
    data = response.json()
    assert "events" in data or "entities" in data or "network" in data

    # Test transformation
    cipr = CloudIPRanges({"json"})
    mock_response = [response]

    transformed = transform(cipr, mock_response, "vercel")
    assert "provider" in transformed
    assert "method" in transformed


@pytest.mark.integration
def test_seed_cidr_end_to_end(skip_if_no_internet, rate_limit_delay):
    """Test complete end-to-end workflow for seed CIDR provider."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        cipr = CloudIPRanges({"json"})
        cipr.base_url = temp_path

        # Test Vercel (seed CIDR provider)
        provider = "vercel"
        result = cipr._fetch_and_save(provider)

        assert result is not None
        ipv4_count, ipv6_count = result
        assert ipv4_count >= 0 and ipv6_count >= 0

        # Check output file
        output_file = temp_path / f"{provider}.json"
        assert output_file.exists()

        # Validate file content
        import json
        with open(output_file, 'r') as f:
            saved_data = json.load(f)

        assert saved_data["provider"] == "Vercel"
        assert saved_data["method"] == "rdap_registry"
        assert len(saved_data["ipv4"]) > 0 or len(saved_data["ipv6"]) > 0


@pytest.mark.integration
def test_multiple_seed_cidrs(skip_if_no_internet, rate_limit_delay):
    """Test handling multiple seed CIDRs for a single provider."""
    cipr = CloudIPRanges({"json"})

    # Vercel has multiple seed CIDRs
    provider = "vercel"
    seeds = cipr.sources[provider]

    assert len(seeds) > 1, "Vercel should have multiple seed CIDRs"

    # Each seed should be valid CIDR notation
    import ipaddress
    for seed in seeds:
        ipaddress.ip_network(seed, strict=False)
        assert "/" in seed, f"Seed {seed} should be in CIDR format"

    # Test that all seeds are processed
    result = fetch_and_save_seed_cidr_source(cipr, provider, seeds)

    # Should have IP ranges from multiple seeds
    assert len(result["ipv4"]) > 0, "Should have IPv4 ranges from seeds"

    # The result should aggregate data from all seeds
    assert result["method"] == "rdap_registry"
    assert "coverage_notes" in result


@pytest.mark.integration
def test_rdap_error_handling(skip_if_no_internet, rate_limit_delay):
    """Test error handling for RDAP lookups."""
    cipr = CloudIPRanges({"json"})

    # Test with invalid IP (should fail gracefully)
    invalid_ip = "999.999.999.999"
    seeds = [f"{invalid_ip}/32"]

    with pytest.raises(Exception):  # Should raise an exception
        fetch_and_save_seed_cidr_source(cipr, "test_provider", seeds)


@pytest.mark.integration
def test_seed_cidr_vs_http_providers(skip_if_no_internet, rate_limit_delay):
    """Test that seed CIDR providers work differently than HTTP providers."""
    cipr = CloudIPRanges({"json"})

    # Seed CIDR provider
    seed_provider = "vercel"
    seed_urls = cipr.sources[seed_provider]

    # HTTP provider
    http_provider = "cloudflare"
    http_urls = cipr.sources[http_provider]

    # Seed CIDRs should not be HTTP URLs
    for seed in seed_urls:
        assert not seed.startswith("http"), f"Seed {seed} should not be HTTP URL"
        assert "/" in seed, f"Seed {seed} should be CIDR format"

    # HTTP URLs should be HTTP URLs
    for url in http_urls:
        assert url.startswith("http"), f"URL {url} should be HTTP URL"
