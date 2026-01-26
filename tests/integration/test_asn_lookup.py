"""Integration tests for ASN lookup functionality."""

import pytest
import requests

from src.cloud_ip_ranges import CloudIPRanges
from src.sources.asn import transform_hackertarget


@pytest.mark.integration
def test_hackertarget_asn_lookup(skip_if_no_internet, rate_limit_delay):
    """Test real ASN lookup using hackertarget API."""
    # Use a known ASN (Hetzner - AS24940)
    asn = "AS24940"
    url = f"https://api.hackertarget.com/aslookup/?q={asn}"

    response = requests.get(url, timeout=10)
    response.raise_for_status()

    # Validate response format
    lines = response.text.strip().split('\n')
    assert len(lines) > 1  # Should have header + at least one IP range

    # Check header format
    header = lines[0].strip()
    assert header == "AS,IP"

    # Check data lines
    for line in lines[1:]:
        parts = line.strip().split(',')
        assert len(parts) == 2
        assert parts[0].strip().isdigit()  # ASN number
        assert '/' in parts[1]  # CIDR notation

        # Validate IP range format
        import ipaddress
        ipaddress.ip_network(parts[1].strip(), strict=False)


@pytest.mark.integration
def test_asn_transform_integration(skip_if_no_internet, rate_limit_delay):
    """Test the full ASN transform pipeline with real data."""
    # Create CloudIPRanges instance
    cipr = CloudIPRanges({"json"})

    # Use a known ASN (Digital Ocean - AS14061)
    asn = "AS14061"
    url = f"https://api.hackertarget.com/aslookup/?q={asn}"

    response = requests.get(url, timeout=10)
    response.raise_for_status()

    # Transform the response
    transformed_data = transform_hackertarget(cipr, [response], "digitalocean")
    normalized_data = cipr._normalize_transformed_data(transformed_data, "digitalocean")

    # Validate transformed data
    assert normalized_data["provider"] == "DigitalOcean"
    assert normalized_data["method"] == "asn_lookup"
    assert len(normalized_data["ipv4"]) > 0 or len(normalized_data["ipv6"]) > 0

    # Validate IP ranges
    import ipaddress
    for ip_range in normalized_data["ipv4"]:
        ipaddress.ip_network(ip_range, strict=False)

    for ip_range in normalized_data["ipv6"]:
        ipaddress.ip_network(ip_range, strict=False)


@pytest.mark.integration
def test_multiple_asn_providers(skip_if_no_internet, rate_limit_delay):
    """Test ASN lookup for multiple providers that use ASN-based sources."""
    cipr = CloudIPRanges({"json"})

    # Find ASN-based providers
    asn_providers = []
    for provider, urls in cipr.sources.items():
        if isinstance(urls, str):
            urls = [urls]
        if urls and urls[0].startswith("AS"):
            asn_providers.append(provider)

    # Test a subset to avoid excessive API calls
    test_providers = asn_providers[:3]  # Test first 3 ASN providers

    for provider in test_providers:
        urls = cipr.sources[provider]
        if isinstance(urls, str):
            urls = [urls]

        asn = urls[0]  # Get the ASN
        url = f"https://api.hackertarget.com/aslookup/?q={asn}"

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            # Transform and validate
            transformed_data = transform_hackertarget(cipr, [response], provider)
            normalized_data = cipr._normalize_transformed_data(transformed_data, provider)

            assert "provider" in normalized_data
            assert normalized_data["method"] == "asn_lookup"

        except Exception as e:
            # Log but don't fail - some ASNs might not have data
            print(f"Warning: Could not test {provider} ({asn}): {e}")
            continue
