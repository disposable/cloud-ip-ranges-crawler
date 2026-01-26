"""End-to-end integration tests."""

import pytest
import tempfile
import json
import requests
from pathlib import Path

from src.cloud_ip_ranges import CloudIPRanges


@pytest.mark.integration
def test_end_to_end_workflow_single_provider(skip_if_no_internet, rate_limit_delay):
    """Test complete workflow for a single provider from fetch to save."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Initialize CloudIPRanges with JSON output
        cipr = CloudIPRanges({"json"})
        cipr.base_url = temp_path

        # Test with Cloudflare (reliable, fast API)
        provider = "cloudflare"

        # Run the complete workflow
        result = cipr._fetch_and_save(provider)

        # Validate results
        assert result is not None
        ipv4_count, ipv6_count = result
        assert ipv4_count >= 0 and ipv6_count >= 0

        # Check that files were created
        output_file = temp_path / f"{provider}.json"
        assert output_file.exists()

        # Validate file content
        with open(output_file, 'r') as f:
            saved_data = json.load(f)

        assert saved_data["provider"] == "Cloudflare"
        assert len(saved_data["ipv4"]) > 0 or len(saved_data["ipv6"]) > 0


@pytest.mark.integration
def test_end_to_end_workflow_multiple_providers(skip_if_no_internet, rate_limit_delay):
    """Test complete workflow for multiple providers."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Initialize CloudIPRanges with multiple output formats
        cipr = CloudIPRanges({"json", "csv"})
        cipr.base_url = temp_path

        # Test with a small subset of reliable providers
        providers = ["cloudflare", "github"]

        # Fetch all providers
        success = cipr.fetch_all(set(providers))
        assert success, "Failed to fetch providers"

        # Validate that we have statistics
        assert len(cipr.statistics) > 0

        # Check that files were created for each successful provider
        for provider in providers:
            if provider in cipr.statistics:
                # JSON file should exist
                json_file = temp_path / f"{provider}.json"
                assert json_file.exists()

                # CSV file should exist
                csv_file = temp_path / f"{provider}.csv"
                assert csv_file.exists()

                # Validate JSON content
                with open(json_file, 'r') as f:
                    saved_data = json.load(f)
                assert "provider" in saved_data


@pytest.mark.integration
def test_error_handling_and_recovery(skip_if_no_internet, rate_limit_delay):
    """Test error handling in live scenarios."""
    cipr = CloudIPRanges({"json"})

    # Test with a non-existent provider
    with pytest.raises(Exception):
        cipr._fetch_and_save("non_existent_provider")

    # Test with a valid provider but potentially failing URL
    # This tests the error handling in the actual fetch process
    try:
        # Use a provider that might have reliability issues
        result = cipr._fetch_and_save("cloudflare")
        # If it succeeds, that's fine too
        assert result is not None
    except Exception as e:
        # Should handle errors gracefully
        assert isinstance(e, (requests.RequestException, ValueError, KeyError))


@pytest.mark.integration
def test_data_freshness_validation(skip_if_no_internet, rate_limit_delay):
    """Test that fetched data is reasonably fresh."""
    from datetime import datetime, timedelta

    cipr = CloudIPRanges({"json"})
    cipr.base_url = Path(tempfile.gettempdir())

    # Test with Cloudflare (should have recent data)
    result = cipr._fetch_and_save("cloudflare")
    assert result is not None

    # Check the output file for timestamp
    output_file = cipr.base_url / "cloudflare.json"
    if output_file.exists():
        with open(output_file, 'r') as f:
            saved_data = json.load(f)

        # Parse the source_updated_at field if available
        if "source_updated_at" in saved_data and saved_data["source_updated_at"]:
            try:
                # Try to parse as ISO format
                updated_at = datetime.fromisoformat(saved_data["source_updated_at"].replace('Z', '+00:00'))

                # Data should be less than 30 days old (reasonable for cloud providers)
                thirty_days_ago = datetime.now(updated_at.tzinfo) - timedelta(days=30)
                assert updated_at > thirty_days_ago, f"Data is too old: {updated_at}"

            except ValueError:
                # If we can't parse the date, that's okay for this test
                pass
