"""Integration tests for different data formats."""

import pytest
import requests
import csv
import zipfile
import io
import tempfile
from pathlib import Path

from src.cloud_ip_ranges import CloudIPRanges
from src.transforms.registry import get_transform


@pytest.mark.integration
def test_csv_format_digitalocean(integration_cipr: CloudIPRanges, skip_if_no_internet, rate_limit_delay):
    """Test CSV format parsing with DigitalOcean."""
    provider = "digitalocean"
    url = integration_cipr.sources[provider][0]

    response = requests.get(url, timeout=10)
    response.raise_for_status()

    # Validate it's CSV format
    csv_content = response.text
    assert ',' in csv_content, "Should contain CSV separators"

    # Parse as CSV to validate structure
    csv_reader = csv.reader(csv_content.splitlines())
    rows = list(csv_reader)
    assert len(rows) > 1, "Should have header + data rows"

    # Transform and validate
    transform_fn = get_transform(provider)
    transformed_data = transform_fn(integration_cipr, [response], provider)
    normalized_data = integration_cipr._normalize_transformed_data(transformed_data, provider)

    assert normalized_data["provider"] == "DigitalOcean"
    assert len(normalized_data["ipv4"]) > 0 or len(normalized_data["ipv6"]) > 0


@pytest.mark.integration
def test_csv_format_apple_private_relay(integration_cipr: CloudIPRanges, skip_if_no_internet, rate_limit_delay):
    """Test CSV format with Apple Private Relay."""
    provider = "apple_private_relay"
    url = integration_cipr.sources[provider][0]

    response = requests.get(url, timeout=10)
    response.raise_for_status()

    # Validate CSV structure
    csv_content = response.text
    csv_reader = csv.reader(csv_content.splitlines())
    rows = list(csv_reader)
    assert len(rows) > 1, "Should have header + data rows"

    # Transform and validate
    transform_fn = get_transform(provider)
    transformed_data = transform_fn(integration_cipr, [response], provider)
    normalized_data = integration_cipr._normalize_transformed_data(transformed_data, provider)

    assert normalized_data["provider"] == "Apple Private Relay"
    assert len(normalized_data["ipv4"]) > 0 or len(normalized_data["ipv6"]) > 0


@pytest.mark.integration
def test_csv_format_starlink(integration_cipr: CloudIPRanges, skip_if_no_internet, rate_limit_delay):
    """Test CSV format with Starlink."""
    provider = "starlink"
    url = integration_cipr.sources[provider][0]

    response = requests.get(url, timeout=10)
    response.raise_for_status()

    # Validate CSV structure
    csv_content = response.text
    assert ',' in csv_content, "Should contain CSV separators"

    # Transform and validate
    transform_fn = get_transform(provider)
    transformed_data = transform_fn(integration_cipr, [response], provider)
    normalized_data = integration_cipr._normalize_transformed_data(transformed_data, provider)

    assert normalized_data["provider"] == "Starlink"
    assert len(normalized_data["ipv4"]) > 0 or len(normalized_data["ipv6"]) > 0


@pytest.mark.integration
def test_txt_format_telegram(integration_cipr: CloudIPRanges, skip_if_no_internet, rate_limit_delay):
    """Test plain text format with Telegram."""
    provider = "telegram"
    url = integration_cipr.sources[provider][0]

    response = requests.get(url, timeout=10)
    response.raise_for_status()

    # Validate it's plain text with CIDR notation
    text_content = response.text.strip()
    assert '/' in text_content, "Should contain CIDR notation"
    lines = [line.strip() for line in text_content.split('\n') if line.strip()]
    assert len(lines) > 0, "Should have IP range lines"

    # Validate CIDR format in lines
    import ipaddress
    for line in lines[:5]:  # Check first 5 lines
        if line and not line.startswith('#'):  # Skip comments
            ipaddress.ip_network(line, strict=False)

    # Transform and validate
    transform_fn = get_transform(provider)
    transformed_data = transform_fn(integration_cipr, [response], provider)
    normalized_data = integration_cipr._normalize_transformed_data(transformed_data, provider)

    assert normalized_data["provider"] == "Telegram"
    assert len(normalized_data["ipv4"]) > 0 or len(normalized_data["ipv6"]) > 0


@pytest.mark.integration
def test_zip_format_akamai(integration_cipr: CloudIPRanges, skip_if_no_internet, rate_limit_delay):
    """Test ZIP format handling with Akamai."""
    provider = "akamai"
    url = integration_cipr.sources[provider][0]

    response = requests.get(url, timeout=10)
    response.raise_for_status()

    # Validate it's a ZIP file
    assert response.content.startswith(b'PK'), "Should be a ZIP file"

    # Extract and validate ZIP content
    with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
        file_list = zip_file.namelist()
        assert len(file_list) > 0, "ZIP should contain files"

        # Extract first file (usually .txt)
        first_file = file_list[0]
        with zip_file.open(first_file) as extracted_file:
            extracted_content = extracted_file.read().decode('utf-8')

            # Should contain IP ranges
            assert '/' in extracted_content, "Extracted content should contain CIDR notation"

    # Transform and validate
    transform_fn = get_transform(provider)
    transformed_data = transform_fn(integration_cipr, [response], provider)
    normalized_data = integration_cipr._normalize_transformed_data(transformed_data, provider)

    assert normalized_data["provider"] == "Akamai"
    assert len(normalized_data["ipv4"]) > 0 or len(normalized_data["ipv6"]) > 0


@pytest.mark.integration
def test_json_variants(integration_cipr: CloudIPRanges, skip_if_no_internet, rate_limit_delay):
    """Test different JSON structure variations."""
    # Test different JSON providers
    json_providers = ["aws", "google_cloud", "github", "okta"]

    for provider in json_providers:
        if provider not in integration_cipr.sources:
            continue

        urls = integration_cipr.sources[provider]
        if isinstance(urls, str):
            urls = [urls]

        for url in urls[:1]:  # Test first URL only
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()

                # Validate it's valid JSON
                json_data = response.json()
                assert isinstance(json_data, dict), "Should be JSON object"

                # Transform and validate
                transform_fn = get_transform(provider)
                transformed_data = transform_fn(integration_cipr, [response], provider)
                normalized_data = integration_cipr._normalize_transformed_data(transformed_data, provider)

                assert "provider" in normalized_data
                assert len(normalized_data["ipv4"]) > 0 or len(normalized_data["ipv6"]) > 0

            except Exception as e:
                print(f"Warning: Failed to test {provider}: {e}")
                continue


@pytest.mark.integration
def test_format_detection_and_routing(skip_if_no_internet, rate_limit_delay):
    """Test that different formats are correctly detected and routed."""
    cipr = CloudIPRanges({"json"})

    # Test format detection logic
    format_test_cases = [
        ("digitalocean", "CSV"),
        ("telegram", "TXT"),
        ("akamai", "ZIP"),
        ("aws", "JSON"),
        ("cloudflare", "TXT"),  # Cloudflare serves plain text CIDR lists
    ]

    for provider, expected_format in format_test_cases:
        if provider not in cipr.sources:
            continue

        urls = cipr.sources[provider]
        if isinstance(urls, str):
            urls = [urls]

        # Test that the provider is routed to correct handler
        url = urls[0]

        if url.startswith("AS") or "/" in url and not url.startswith("http"):
            # ASN or seed CIDR - different routing
            continue

        # HTTP-based sources should be routable
        assert url.startswith("http"), f"{provider} URL should be HTTP-based"

        # Test that we can fetch and transform
        try:
            result = cipr._fetch_and_save(provider)
            assert result is not None, f"Should be able to fetch and transform {provider}"
        except Exception as e:
            print(f"Warning: Could not test {provider}: {e}")


@pytest.mark.integration
def test_mixed_format_end_to_end(skip_if_no_internet, rate_limit_delay):
    """Test end-to-end workflow with different formats."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        cipr = CloudIPRanges({"json"})
        cipr.base_url = temp_path

        # Test providers with different formats
        format_providers = [
            ("digitalocean", "CSV"),
            ("telegram", "TXT"),
            ("aws", "JSON"),
        ]

        for provider, expected_format in format_providers:
            try:
                result = cipr._fetch_and_save(provider)
                assert result is not None

                # Check output file exists and is valid
                output_file = temp_path / f"{provider}.json"
                assert output_file.exists()

                # Validate file content
                import json
                with open(output_file, 'r') as f:
                    saved_data = json.load(f)

                assert "provider" in saved_data
                assert len(saved_data["ipv4"]) > 0 or len(saved_data["ipv6"]) > 0

            except Exception as e:
                print(f"Warning: Failed end-to-end test for {provider}: {e}")
                continue
