"""Integration tests for live provider APIs."""

import pytest
import requests

from src.cloud_ip_ranges import CloudIPRanges
from src.transforms.registry import get_transform


@pytest.mark.integration
@pytest.mark.parametrize("provider", ["cloudflare", "aws", "github", "exoscale", "backblaze"])
def test_live_provider_api(integration_cipr: CloudIPRanges, provider: str, skip_if_no_internet, rate_limit_delay):
    """Test fetching and transforming data from live provider APIs."""
    # Get the source URLs for the provider
    sources = integration_cipr.sources
    assert provider in sources, f"Provider {provider} not found in sources"

    urls = sources[provider]
    if isinstance(urls, str):
        urls = [urls]

    # Skip ASN-based sources for this test
    if urls and urls[0].startswith("AS"):
        pytest.skip(f"Skipping ASN-based source: {provider}")

    # Make real HTTP request
    for url in urls:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        # Transform the response using the actual transform function
        transform_fn = get_transform(provider)
        transformed_data = transform_fn(integration_cipr, [response], provider)
        normalized_data = integration_cipr._normalize_transformed_data(transformed_data, provider)

        # Validate the transformed data
        assert "provider" in normalized_data
        assert "method" in normalized_data
        assert "ipv4" in normalized_data or "ipv6" in normalized_data
        assert isinstance(normalized_data["ipv4"], list)
        assert isinstance(normalized_data["ipv6"], list)

        # Validate IP ranges format if present
        if normalized_data["ipv4"]:
            import ipaddress

            for ip_range in normalized_data["ipv4"]:
                ipaddress.ip_network(ip_range, strict=False)

        if normalized_data["ipv6"]:
            import ipaddress

            for ip_range in normalized_data["ipv6"]:
                ipaddress.ip_network(ip_range, strict=False)


@pytest.mark.integration
def test_cloudflare_live_api(integration_cipr: CloudIPRanges, skip_if_no_internet, rate_limit_delay):
    """Specific test for Cloudflare's live API - known reliable endpoint."""
    url = "https://api.cloudflare.com/client/v4/ips"

    response = requests.get(url, timeout=10)
    response.raise_for_status()

    # Validate Cloudflare-specific response structure
    data = response.json()
    assert "result" in data
    assert "ipv4_cidrs" in data["result"] or "ipv6_cidrs" in data["result"]

    # Transform and validate
    transform_fn = get_transform("cloudflare")
    transformed_data = transform_fn(integration_cipr, [response], "cloudflare")
    normalized_data = integration_cipr._normalize_transformed_data(transformed_data, "cloudflare")

    assert normalized_data["provider"] == "Cloudflare"
    assert normalized_data["method"] == "published_list"
    assert len(normalized_data["ipv4"]) > 0 or len(normalized_data["ipv6"]) > 0


@pytest.mark.integration
def test_exoscale_live_api(integration_cipr: CloudIPRanges, skip_if_no_internet, rate_limit_delay):
    """Test Exoscale JSON API."""
    url = "https://exoscale-prefixes.sos-ch-dk-2.exo.io/exoscale_prefixes.json"

    response = requests.get(url, timeout=10)
    response.raise_for_status()

    # Validate Exoscale-specific response structure
    data = response.json()
    assert "prefixes" in data

    # Check for IPv4Prefix/IPv6Prefix fields
    prefixes = data["prefixes"]
    if prefixes:
        prefix = prefixes[0]
        assert "IPv4Prefix" in prefix or "IPv6Prefix" in prefix or "prefix" in prefix

    # Transform and validate
    transform_fn = get_transform("exoscale")
    transformed_data = transform_fn(integration_cipr, [response], "exoscale")
    normalized_data = integration_cipr._normalize_transformed_data(transformed_data, "exoscale")

    assert normalized_data["provider"] == "Exoscale"
    assert normalized_data["method"] == "published_list"
    assert len(normalized_data["ipv4"]) > 0 or len(normalized_data["ipv6"]) > 0


@pytest.mark.integration
def test_backblaze_live_api(integration_cipr: CloudIPRanges, skip_if_no_internet, rate_limit_delay):
    """Test Backblaze HTML documentation."""
    url = "https://www.backblaze.com/computer-backup/docs/backblaze-ip-addresses"

    response = requests.get(url, timeout=10)
    response.raise_for_status()

    # Validate HTML response contains CIDR patterns
    content = response.text
    assert "45.11.36.0/22" in content  # Known Backblaze range

    # Transform and validate
    transform_fn = get_transform("backblaze")
    transformed_data = transform_fn(integration_cipr, [response], "backblaze")
    normalized_data = integration_cipr._normalize_transformed_data(transformed_data, "backblaze")

    assert normalized_data["provider"] == "Backblaze"
    assert normalized_data["method"] == "published_list"
    assert len(normalized_data["ipv4"]) > 0 or len(normalized_data["ipv6"]) > 0

    # Check for known Backblaze ranges
    assert "45.11.36.0/22" in normalized_data["ipv4"]


@pytest.mark.integration
def test_aws_live_api(integration_cipr: CloudIPRanges, skip_if_no_internet, rate_limit_delay):
    """Test AWS IP ranges API."""
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"

    response = requests.get(url, timeout=10)
    response.raise_for_status()

    # Validate AWS-specific response structure
    data = response.json()
    assert "prefixes" in data or "ipv6_prefixes" in data

    # Transform and validate
    transform_fn = get_transform("aws")
    transformed_data = transform_fn(integration_cipr, [response], "aws")
    normalized_data = integration_cipr._normalize_transformed_data(transformed_data, "aws")

    assert normalized_data["provider"] in ["Amazon Web Services", "Aws"]
    assert len(normalized_data["ipv4"]) > 0 or len(normalized_data["ipv6"]) > 0
