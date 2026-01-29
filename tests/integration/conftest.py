"""Configuration for integration tests."""

import pytest

from src.cloud_ip_ranges import CloudIPRanges


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "integration: marks tests as integration tests (require internet)")


@pytest.fixture(scope="session")
def integration_cipr() -> CloudIPRanges:
    """CloudIPRanges instance configured for integration tests."""
    return CloudIPRanges({"json"})


@pytest.fixture(scope="session")
def skip_if_no_internet():
    """Skip test if no internet connectivity."""
    try:
        import requests

        response = requests.get("https://httpbin.org/status/200", timeout=5)
        response.raise_for_status()
    except Exception:
        pytest.skip("No internet connectivity for integration tests")


@pytest.fixture
def rate_limit_delay():
    """Add delay between requests to avoid rate limiting."""
    import time

    yield
    time.sleep(1)  # 1 second delay between requests


@pytest.fixture
def sample_providers():
    """Return a subset of providers for integration testing to avoid excessive API calls."""
    return [
        "cloudflare",  # Fast, reliable JSON API
        "aws",  # Official JSON API
        "github",  # Simple JSON API
    ]
