"""Integration tests for error recovery and retry logic.

Fault injection through the real code paths — assertions verify externally
observable effects (files, statistics, merged output), never just that a
mock was called or that "no exception happened".
"""

import json
from unittest.mock import Mock, patch

import pytest
import requests

from cloud_ip_ranges import CloudIPRanges
from transforms.common import validate_ip


def _cipr_with_google(tmp_path, **kwargs):
    cipr = CloudIPRanges({"json"}, **kwargs)
    cipr.output_dir = tmp_path
    cipr.sources = {"google_cloud": ["https://example.com/prefixes.json"]}
    return cipr


def _google_resp():
    resp = Mock(spec=requests.Response)
    resp.status_code = 200
    resp.headers = {}
    resp.text = "{}"
    resp.raise_for_status.return_value = None
    resp.json.return_value = {
        "creationTime": "2024-01-01T00:00:00",
        "prefixes": [{"ipv4Prefix": "8.8.4.0/24"}],
    }
    return resp


@pytest.mark.integration
def test_network_timeout_handling(tmp_path):
    """A timeout must fail the source, not crash the run, and write no file."""
    cipr = _cipr_with_google(tmp_path)
    with patch.object(cipr.session, "get", side_effect=requests.exceptions.Timeout("timed out")):
        assert cipr.fetch_all({"google_cloud"}) is False
    assert not (tmp_path / "google-cloud.json").exists()
    assert "google_cloud" not in cipr.statistics


@pytest.mark.integration
def test_http_error_handling(tmp_path):
    """HTTP error status must fail the source with no partial output."""
    cipr = _cipr_with_google(tmp_path)
    resp = _google_resp()
    resp.raise_for_status.side_effect = requests.exceptions.HTTPError("503")
    with patch.object(cipr.session, "get", return_value=resp):
        assert cipr.fetch_all({"google_cloud"}) is False
    assert not (tmp_path / "google-cloud.json").exists()


@pytest.mark.integration
def test_connection_error_handling(tmp_path):
    """Connection failure must fail the source and leave the dir clean."""
    cipr = _cipr_with_google(tmp_path)
    with patch.object(cipr.session, "get", side_effect=requests.exceptions.ConnectionError()):
        assert cipr.fetch_all({"google_cloud"}) is False
    assert list(tmp_path.glob("*.json")) == []


@pytest.mark.integration
def test_provider_failure_recovery(tmp_path):
    """A failed provider must not sink siblings; successful ones write files."""
    cipr = CloudIPRanges({"json"})
    cipr.output_dir = tmp_path
    cipr.sources = {"a_ok": ["u1"], "b_bad": ["u2"], "c_ok": ["u3"]}

    payload = {
        "provider": "T",
        "provider_id": "x",
        "ipv4": ["8.8.8.0/24"],
        "ipv6": [],
        "details_ipv4": [],
        "details_ipv6": [],
        "last_update": "t",
        "source": ["u"],
    }

    def fake_fetch(key):
        if key == "b_bad":
            raise requests.exceptions.ConnectionError("down")
        cipr._save_json(dict(payload, provider_id=key), f"{key}.json")
        return (1, 0)

    with patch.object(cipr, "_fetch_and_save", side_effect=fake_fetch):
        result = cipr.fetch_all()

    assert result is False
    assert "b_bad" not in cipr.statistics
    assert set(cipr.statistics) == {"a_ok", "c_ok"}
    # Observable side effects: the good providers' files exist and parse.
    for ok in ("a_ok", "c_ok"):
        assert json.loads((tmp_path / f"{ok}.json").read_text())["ipv4"] == ["8.8.8.0/24"]


@pytest.mark.integration
def test_invalid_json_handling(tmp_path):
    """Malformed JSON body must fail the source and preserve the old file."""
    cipr = _cipr_with_google(tmp_path)
    existing = tmp_path / "google-cloud.json"
    existing.write_text(json.dumps({"provider_id": "google_cloud", "ipv4": ["8.8.8.0/24"], "ipv6": []}))
    before = existing.read_bytes()

    resp = _google_resp()
    resp.json.side_effect = ValueError("Invalid JSON")
    with patch.object(cipr.session, "get", return_value=resp):
        assert cipr.fetch_all({"google_cloud"}) is False

    assert existing.read_bytes() == before


@pytest.mark.integration
def test_malformed_data_handling():
    """validate_ip rejects malformed and non-public ranges, keeps public ones."""
    assert validate_ip("192.168.1.0/24") is None  # private
    assert validate_ip("8.8.8.0/24") == "8.8.8.0/24"
    assert validate_ip("not-an-ip") is None
    assert validate_ip("999.999.999.999/24") is None
    assert validate_ip("192.168.1.0/33") is None


@pytest.mark.integration
def test_session_retry_configuration():
    """The session must have a retry-enabled adapter mounted for http(s)."""
    cipr = CloudIPRanges({"json"})
    for prefix in ("http://", "https://"):
        adapter = cipr.session.adapters[prefix]
        retries = adapter.max_retries
        assert retries.total > 0, f"{prefix} adapter has no retries configured"


@pytest.mark.integration
def test_partial_url_failure_multi_url(tmp_path):
    """When one of a provider's URLs fails, no provider file may be written."""
    cipr = CloudIPRanges({"json"})
    cipr.output_dir = tmp_path
    cipr.sources = {"google_cloud": ["https://example.com/a.json", "https://example.com/b.json"]}

    def flaky(url, **kwargs):
        if url.endswith("/b.json"):
            raise requests.exceptions.ConnectionError("Simulated failure")
        return _google_resp()

    with patch.object(cipr.session, "get", side_effect=flaky):
        with pytest.raises(RuntimeError, match="Failed to fetch"):
            cipr._fetch_and_save("google_cloud")
    assert not (tmp_path / "google-cloud.json").exists()


@pytest.mark.integration
def test_empty_response_handling(tmp_path):
    """An empty body yields no prefixes — the source must fail cleanly."""
    cipr = _cipr_with_google(tmp_path)
    resp = _google_resp()
    resp.json.return_value = {}
    resp.text = ""
    with patch.object(cipr.session, "get", return_value=resp):
        assert cipr.fetch_all({"google_cloud"}) is False
    assert not (tmp_path / "google-cloud.json").exists()


@pytest.mark.integration
def test_large_response_handling(skip_if_no_internet, rate_limit_delay):
    """AWS publishes a large prefix list — fetch it end-to-end live."""
    cipr = CloudIPRanges({"json"})
    ipv4_count, _ = cipr._fetch_and_save("aws")
    assert ipv4_count > 100, "AWS should have many IPv4 ranges"


@pytest.mark.integration
def test_concurrent_writes_are_safe(tmp_path):
    """Concurrent saves to different provider files produce complete files."""
    import threading

    cipr = CloudIPRanges({"json"})
    cipr.output_dir = tmp_path
    errors = []

    def save(key):
        try:
            cipr._save_json({"provider_id": key, "ipv4": ["8.8.8.0/24"], "ipv6": []}, f"{key}.json")
        except Exception as e:  # noqa: BLE001 - collect for assertion
            errors.append(e)

    threads = [threading.Thread(target=save, args=(f"prov{i}",)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    for i in range(5):
        assert json.loads((tmp_path / f"prov{i}.json").read_text())["ipv4"] == ["8.8.8.0/24"]
