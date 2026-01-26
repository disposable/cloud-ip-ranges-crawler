# Integration Tests

This directory contains integration tests for the cloud-ip-ranges project.

## Purpose

Integration tests validate the complete workflow against live APIs and real data, complementing the unit tests that use mocked responses.

## Test Coverage

- **Live API Tests** (`test_live_apis.py`): Tests real HTTP requests to provider APIs
- **ASN Lookup Tests** (`test_asn_lookup.py`): Tests ASN lookup functionality using hackertarget API
- **End-to-End Tests** (`test_end_to_end.py`): Tests complete workflow from fetch to save

## Running Integration Tests

### Prerequisites
- Internet connectivity
- No API keys required (uses public endpoints only)

### Run All Integration Tests
```bash
pytest -m integration
```

### Run Specific Test File
```bash
pytest tests/integration/test_live_apis.py
```

### Run With Verbose Output
```bash
pytest -m integration -v
```

## Test Configuration

Integration tests are marked with `@pytest.mark.integration` and are skipped by default in regular test runs.

### Rate Limiting
Tests include built-in delays between requests to avoid rate limiting:
- 1-second delay between API calls
- Limited subset of providers tested
- Graceful handling of failed requests

### CI/CD Integration
Integration tests run in CI only when:
- Manually triggered (`workflow_dispatch`)
- On main branch pushes
- Environment variable `INTEGRATION_TESTS=true`

## Test Data

Integration tests use live data from:
- **Cloudflare**: IP ranges API
- **AWS**: IP ranges JSON
- **GitHub**: Meta API
- **Hackertarget**: ASN lookup service

## Error Handling

Tests are designed to be resilient:
- Network timeouts are handled gracefully
- API failures don't fail the entire test suite
- Missing or malformed data is logged but doesn't crash tests

## Adding New Integration Tests

1. Create test file in `tests/integration/`
2. Add `@pytest.mark.integration` decorator
3. Use `skip_if_no_internet` fixture for connectivity checks
4. Add `rate_limit_delay` fixture for API rate limiting
5. Follow existing patterns for error handling

Example:
```python
@pytest.mark.integration
def test_new_provider_api(integration_cipr, skip_if_no_internet, rate_limit_delay):
    # Test implementation here
    pass
```
