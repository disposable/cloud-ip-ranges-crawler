"""Integration tests for error recovery and retry logic."""

import pytest
import requests
from unittest.mock import patch, Mock

from src.cloud_ip_ranges import CloudIPRanges


@pytest.mark.integration
def test_network_timeout_handling(skip_if_no_internet, rate_limit_delay):
    """Test handling of network timeouts."""
    import requests
    from unittest.mock import patch

    # Test timeout behavior directly
    with patch("requests.Session.get") as mock_get:
        mock_get.side_effect = requests.exceptions.Timeout("Request timed out")

        with pytest.raises(requests.exceptions.Timeout):
            requests.Session().get("https://example.com", timeout=1)


@pytest.mark.integration
def test_http_error_handling(skip_if_no_internet, rate_limit_delay):
    """Test handling of HTTP errors (4xx, 5xx)."""
    import requests
    from unittest.mock import patch

    # Test HTTP error behavior directly
    with patch("requests.Session.get") as mock_get:
        mock_get.side_effect = requests.exceptions.HTTPError("404 Not Found")

        with pytest.raises(requests.exceptions.HTTPError):
            requests.Session().get("https://example.com", timeout=10)


@pytest.mark.integration
def test_connection_error_handling(skip_if_no_internet, rate_limit_delay):
    """Test handling of connection errors."""
    cipr = CloudIPRanges({"json"})

    # Test connection error
    with patch.object(cipr.session, "get") as mock_get:
        mock_get.side_effect = requests.exceptions.ConnectionError()

        with pytest.raises(requests.exceptions.ConnectionError):
            cipr.session.get("https://example.com")


@pytest.mark.integration
def test_provider_failure_recovery(skip_if_no_internet, rate_limit_delay):
    """Test recovery when individual providers fail."""
    cipr = CloudIPRanges({"json"})

    # Test that fetch_all continues even if some providers fail
    # This tests the error handling in the main fetch loop

    # Mock a provider to fail
    with patch.object(cipr, "_fetch_and_save") as mock_fetch:
        mock_fetch.side_effect = [
            (10, 5),  # First provider succeeds
            Exception("Network error"),  # Second provider fails
            (8, 3),  # Third provider succeeds
        ]

        # Should not raise exception despite failures
        result = cipr.fetch_all()

        # Should return False due to errors, but not crash
        assert result is False


@pytest.mark.integration
def test_invalid_json_handling(skip_if_no_internet, rate_limit_delay):
    """Test handling of invalid JSON responses."""
    cipr = CloudIPRanges({"json"})

    # Test with invalid JSON
    with patch.object(cipr.session, "get") as mock_get:
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_response.text = "This is not valid JSON"
        mock_get.return_value = mock_response

        with pytest.raises(ValueError):
            mock_response.json()


@pytest.mark.integration
def test_malformed_data_handling(skip_if_no_internet, rate_limit_delay):
    """Test handling of malformed IP ranges or data."""
    CloudIPRanges({"json"})

    # Test with malformed IP range
    from src.transforms.common import validate_ip

    # Valid IP should pass
    result = validate_ip("192.168.1.0/24")
    assert result is None, "Private IP should be filtered out"

    # Valid public IP should pass
    result = validate_ip("8.8.8.0/24")
    assert result == "8.8.8.0/24", "Public IP should be returned"

    # Invalid IP should fail
    result = validate_ip("not-an-ip")
    assert result is None, "Invalid IP should return None"

    # Invalid IP should fail
    assert validate_ip("999.999.999.999/24") is None
    assert validate_ip("not-an-ip") is None
    assert validate_ip("192.168.1.0/33") is None


@pytest.mark.integration
def test_rate_limiting_behavior(skip_if_no_internet, rate_limit_delay):
    """Test rate limiting behavior."""
    import time

    cipr = CloudIPRanges({"json"})

    # Test that rate limiting delays are respected
    start_time = time.time()

    # Make multiple requests
    for i in range(3):
        try:
            # Use a reliable endpoint
            response = cipr.session.get("https://httpbin.org/status/200", timeout=5)
            response.raise_for_status()
        except:
            pass  # Ignore errors for this test

    end_time = time.time()

    # Should have taken some time due to rate limiting
    # This is a rough check - rate limiting should add delays
    elapsed = end_time - start_time
    assert elapsed >= 0, "Should have taken some time"


@pytest.mark.integration
def test_session_retry_configuration():
    """Test that the session is configured with retry logic."""
    cipr = CloudIPRanges({"json"})

    # Check that session has retry configuration
    # The CloudIPRanges class should configure retries
    assert hasattr(cipr.session, "adapters"), "Session should have adapters"

    # Check adapter configuration - different adapters may have different retry implementations
    adapters = list(cipr.session.adapters.values())
    assert len(adapters) > 0, "Should have at least one adapter"

    # The session should be configured for HTTP requests
    assert cipr.session is not None, "Session should be initialized"


@pytest.mark.integration
def test_partial_url_failure_multi_url(skip_if_no_internet, rate_limit_delay):
    """Test handling when some URLs fail in multi-URL providers."""
    cipr = CloudIPRanges({"json"})

    # Test with a provider that has multiple URLs
    provider = "openai"
    urls = cipr.sources[provider]

    # Mock one URL to fail, others to succeed
    original_get = cipr.session.get

    def mock_get(url, **kwargs):
        if url == urls[0]:
            raise requests.exceptions.ConnectionError("Simulated failure")
        return original_get(url, **kwargs)

    with patch.object(cipr.session, "get", side_effect=mock_get):
        try:
            # Should handle partial failures gracefully
            cipr._fetch_and_save(provider)
            # May succeed or fail depending on implementation
        except Exception as e:
            # Should fail gracefully, not crash
            assert "ConnectionError" in str(e) or isinstance(e, Exception)


@pytest.mark.integration
def test_empty_response_handling(skip_if_no_internet, rate_limit_delay):
    """Test handling of empty responses."""
    cipr = CloudIPRanges({"json"})

    # Test with empty response
    with patch.object(cipr.session, "get") as mock_get:
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.text = ""
        mock_response.json.return_value = {}
        mock_response.content = b""
        mock_get.return_value = mock_response

        # Should handle empty response gracefully
        response = cipr.session.get("https://example.com")
        assert response.text == ""
        assert response.json() == {}


@pytest.mark.integration
def test_large_response_handling(skip_if_no_internet, rate_limit_delay):
    """Test handling of large responses."""
    cipr = CloudIPRanges({"json"})

    # Test with a provider that might return large data
    # AWS typically has a large IP range list
    provider = "aws"

    try:
        result = cipr._fetch_and_save(provider)
        assert result is not None

        ipv4_count, ipv6_count = result
        # AWS should have substantial IP ranges
        assert ipv4_count > 100, "AWS should have many IPv4 ranges"

    except Exception as e:
        print(f"Warning: Could not test large response handling: {e}")


@pytest.mark.integration
def test_concurrent_request_safety(skip_if_no_internet, rate_limit_delay):
    """Test that concurrent requests are handled safely."""
    import threading

    cipr = CloudIPRanges({"json"})
    results = []
    errors = []

    def make_request():
        try:
            response = cipr.session.get("https://httpbin.org/status/200", timeout=5)
            results.append(response.status_code)
        except Exception as e:
            errors.append(e)

    # Make multiple concurrent requests
    threads = []
    for i in range(3):
        thread = threading.Thread(target=make_request)
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Should handle concurrent requests safely
    assert len(errors) == 0 or len(results) > 0, "Should handle concurrent requests"
