"""Integration tests for multi-URL providers."""

import pytest
import requests
import tempfile
from pathlib import Path

from src.cloud_ip_ranges import CloudIPRanges
from src.transforms.registry import get_transform


@pytest.mark.integration
@pytest.mark.parametrize("provider", ["openai", "stripe"])
def test_multi_url_providers(integration_cipr: CloudIPRanges, provider: str, skip_if_no_internet, rate_limit_delay):
    """Test providers with multiple URLs."""
    # Get the source URLs for the provider
    sources = integration_cipr.sources
    assert provider in sources, f"Provider {provider} not found in sources"

    urls = sources[provider]
    assert isinstance(urls, list), f"Provider {provider} should have multiple URLs"
    assert len(urls) > 1, f"Provider {provider} should have more than one URL"

    # Test each URL individually
    all_responses = []
    for url in urls:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        all_responses.append(response)

    # Transform all responses together
    transform_fn = get_transform(provider)
    transformed_data = transform_fn(integration_cipr, all_responses, provider)
    normalized_data = integration_cipr._normalize_transformed_data(transformed_data, provider)

    # Validate the combined result
    assert "provider" in normalized_data
    assert "ipv4" in normalized_data or "ipv6" in normalized_data
    assert isinstance(normalized_data["ipv4"], list)
    assert isinstance(normalized_data["ipv6"], list)

    # Should have data from multiple URLs
    total_ips = len(normalized_data["ipv4"]) + len(normalized_data["ipv6"])
    assert total_ips > 0, f"Should have IP ranges from {provider}"


@pytest.mark.integration
def test_grafana_cloud_multi_url(integration_cipr: CloudIPRanges, skip_if_no_internet, rate_limit_delay):
    """Test Grafana Cloud provider with many URLs."""
    provider = "grafana_cloud"
    urls = integration_cipr.sources[provider]

    # Grafana Cloud has many URLs (7+ different service endpoints)
    assert len(urls) >= 5, f"Grafana Cloud should have many URLs, got {len(urls)}"

    # Test a subset to avoid excessive API calls
    test_urls = urls[:3]  # Test first 3 URLs
    responses = []

    for url in test_urls:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        responses.append(response)

    # Transform the responses
    transform_fn = get_transform(provider)
    transformed_data = transform_fn(integration_cipr, responses, provider)
    normalized_data = integration_cipr._normalize_transformed_data(transformed_data, provider)

    # Validate result
    assert normalized_data["provider"] == "Grafana Cloud"
    assert len(normalized_data["ipv4"]) > 0 or len(normalized_data["ipv6"]) > 0


@pytest.mark.integration
def test_intercom_multi_region_urls(integration_cipr: CloudIPRanges, skip_if_no_internet, rate_limit_delay):
    """Test Intercom provider with multi-region URLs."""
    provider = "intercom"
    urls = integration_cipr.sources[provider]

    # Intercom has multiple regional endpoints
    assert len(urls) >= 3, f"Intercom should have multiple regional URLs"

    # Check that URLs are from different regions
    regions = []
    for url in urls:
        if "us" in url:
            regions.append("us")
        elif "eu" in url:
            regions.append("eu")
        elif "au" in url:
            regions.append("au")

    assert len(set(regions)) >= 2, "Should have URLs from multiple regions"

    # Test each region
    responses = []
    for url in urls:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        responses.append(response)

    # Transform and validate
    transform_fn = get_transform(provider)
    transformed_data = transform_fn(integration_cipr, responses, provider)
    normalized_data = integration_cipr._normalize_transformed_data(transformed_data, provider)

    assert normalized_data["provider"] == "Intercom"
    assert len(normalized_data["ipv4"]) > 0 or len(normalized_data["ipv6"]) > 0


@pytest.mark.integration
def test_multi_url_end_to_end(skip_if_no_internet, rate_limit_delay):
    """Test end-to-end workflow for multi-URL providers."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        cipr = CloudIPRanges({"json"})
        cipr.base_url = temp_path

        # Test OpenAI (multi-URL provider)
        provider = "openai"
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

        assert saved_data["provider"] == "OpenAI"
        assert len(saved_data["ipv4"]) > 0 or len(saved_data["ipv6"]) > 0


@pytest.mark.integration
def test_multi_url_error_handling(integration_cipr: CloudIPRanges, skip_if_no_internet, rate_limit_delay):
    """Test error handling when some URLs fail in multi-URL providers."""
    provider = "stripe"
    urls = integration_cipr.sources[provider]

    # Test that provider works with all URLs
    responses = []
    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            responses.append(response)
        except Exception as e:
            # Log but continue - some URLs might fail
            print(f"Warning: Failed to fetch {url}: {e}")
            continue

    # Should have at least one successful response
    assert len(responses) > 0, f"Should have at least one successful response for {provider}"

    # Transform with available responses
    transform_fn = get_transform(provider)
    transformed_data = transform_fn(integration_cipr, responses, provider)
    normalized_data = integration_cipr._normalize_transformed_data(transformed_data, provider)

    # Should still get valid data even with some failures
    assert "provider" in normalized_data
    assert len(normalized_data["ipv4"]) > 0 or len(normalized_data["ipv6"]) > 0


@pytest.mark.integration
def test_url_aggregation_logic(integration_cipr: CloudIPRanges, skip_if_no_internet, rate_limit_delay):
    """Test that multiple URLs are properly aggregated."""
    provider = "openai"
    urls = integration_cipr.sources[provider]

    # Fetch each URL separately
    individual_results = []
    for url in urls:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        # Transform single URL
        transform_fn = get_transform(provider)
        single_result = transform_fn(integration_cipr, [response], provider)
        individual_results.append(single_result)

    # Fetch all URLs together
    all_responses = []
    for url in urls:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        all_responses.append(response)

    transform_fn = get_transform(provider)
    combined_result = transform_fn(integration_cipr, all_responses, provider)
    combined_normalized = integration_cipr._normalize_transformed_data(combined_result, provider)

    # Combined result should have data from all URLs
    total_individual_ips = 0
    for result in individual_results:
        normalized = integration_cipr._normalize_transformed_data(result, provider)
        total_individual_ips += len(normalized["ipv4"]) + len(normalized["ipv6"])

    combined_ips = len(combined_normalized["ipv4"]) + len(combined_normalized["ipv6"])

    # Combined should have at least as many IPs as individual (after deduplication)
    assert combined_ips >= total_individual_ips * 0.8, "Combined result should aggregate data from all URLs"
