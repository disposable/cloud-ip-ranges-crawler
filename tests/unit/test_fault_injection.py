"""Fault injection: dependencies misbehaving at system boundaries.

Every test drives the real code path (session.get / cycletls client / whois /
file writes) and asserts externally observable effects — files written or
absent, statistics, merged output — not just "an exception happened".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
import requests

import sources.cycletls as cycletls_mod
from cloud_ip_ranges import CloudIPRanges
from sources.http import fetch_and_save_http_source


def _ok_response(json_data: Any = None, text: str = "", status: int = 200) -> Mock:
    resp = Mock(spec=requests.Response)
    resp.status_code = status
    resp.text = text
    resp.headers = {}
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


def _seed_existing(cipr: CloudIPRanges, source_key: str, ipv4: list[str] | None = None) -> Path:
    """Pre-write a provider JSON as a previous successful run would have."""
    path = cipr.output_dir / f"{source_key.replace('_', '-')}.json"
    path.write_text(
        json.dumps({
            "provider": "Test",
            "provider_id": source_key,
            "ipv4": ipv4 or ["8.8.8.0/24"],
            "ipv6": [],
            "details_ipv4": [],
            "details_ipv6": [],
        })
    )
    return path


def _google_payload() -> dict:
    return {
        "creationTime": "2024-01-01T00:00:00",
        "prefixes": [{"ipv4Prefix": "8.8.4.0/24", "service": "GOOGLE", "scope": "global"}],
    }


class TestHttpSourceFaults:
    @pytest.fixture()
    def crawler(self, tmp_path: Path) -> CloudIPRanges:
        cipr = CloudIPRanges({"json"}, merge_all_providers=True)
        cipr.output_dir = tmp_path
        cipr.sources = {"google_cloud": ["https://example.com/prefixes.json"]}
        return cipr

    def test_timeout_preserves_previous_file_and_reuses_data(self, crawler: CloudIPRanges, monkeypatch: pytest.MonkeyPatch) -> None:
        existing = _seed_existing(crawler, "google_cloud")
        before = existing.read_bytes()

        monkeypatch.setattr(crawler.session, "get", Mock(side_effect=requests.exceptions.Timeout("timed out")))

        assert crawler.fetch_all({"google_cloud"}) is False

        # Observable: previous file untouched byte-for-byte, failure recorded,
        # and the previous data still flows into the merged output.
        assert existing.read_bytes() == before
        assert crawler.statistics["google_cloud"] == {"ipv4": 1, "ipv6": 0}
        merged = json.loads((crawler.output_dir / "all-providers.json").read_text())
        assert "8.8.8.0/24" in merged["ipv4"]

    def test_connection_error_no_previous_data_means_no_output(self, crawler: CloudIPRanges, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(crawler.session, "get", Mock(side_effect=requests.exceptions.ConnectionError("refused")))

        assert crawler.fetch_all({"google_cloud"}) is False

        # No file, no stats, and the merged output is empty — not a half-file.
        assert not (crawler.output_dir / "google-cloud.json").exists()
        assert "google_cloud" not in crawler.statistics
        assert not crawler.ip_merger.has_data

    def test_http_500_response_fails_source(self, crawler: CloudIPRanges, monkeypatch: pytest.MonkeyPatch) -> None:
        resp = _ok_response()
        resp.raise_for_status.side_effect = requests.exceptions.HTTPError("500 Server Error")
        monkeypatch.setattr(crawler.session, "get", Mock(return_value=resp))

        with pytest.raises(RuntimeError, match="Failed to fetch google_cloud"):
            crawler._fetch_and_save("google_cloud")
        assert not (crawler.output_dir / "google-cloud.json").exists()

    def test_malformed_json_body_fails_source_and_recycles_previous(self, crawler: CloudIPRanges, monkeypatch: pytest.MonkeyPatch) -> None:
        existing = _seed_existing(crawler, "google_cloud", ["8.8.8.0/24"])
        before = existing.read_bytes()

        resp = _ok_response(text="<html>definitely not json</html>")
        resp.json.side_effect = ValueError("No JSON object could be decoded")
        monkeypatch.setattr(crawler.session, "get", Mock(return_value=resp))

        assert crawler.fetch_all({"google_cloud"}) is False
        assert existing.read_bytes() == before
        merged = json.loads((crawler.output_dir / "all-providers.json").read_text())
        assert merged["ipv4"] == ["8.8.8.0/24"]

    def test_partial_response_missing_keys_fails_cleanly(self, crawler: CloudIPRanges, monkeypatch: pytest.MonkeyPatch) -> None:
        # Valid JSON but missing "prefixes" — transform yields nothing.
        monkeypatch.setattr(crawler.session, "get", Mock(return_value=_ok_response(json_data={"creationTime": "t"})))

        with pytest.raises(RuntimeError, match="Failed to parse"):
            crawler._fetch_and_save("google_cloud")
        assert not (crawler.output_dir / "google-cloud.json").exists()

    def test_empty_body_fails_cleanly(self, crawler: CloudIPRanges, monkeypatch: pytest.MonkeyPatch) -> None:
        resp = _ok_response()
        resp.json.side_effect = ValueError("empty")
        monkeypatch.setattr(crawler.session, "get", Mock(return_value=resp))

        assert crawler.fetch_all({"google_cloud"}) is False
        assert not (crawler.output_dir / "google-cloud.json").exists()

    def test_multi_url_partial_failure_does_not_write_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """One URL of several failing must not produce a half-populated provider file."""
        cipr = CloudIPRanges({"json"})
        cipr.output_dir = tmp_path
        cipr.sources = {"google_cloud": ["https://example.com/a.json", "https://example.com/b.json"]}

        def flaky_get(url: str, **kwargs: Any) -> Mock:
            if url.endswith("/b.json"):
                raise requests.exceptions.ConnectionError("dropped")
            return _ok_response(json_data=_google_payload())

        monkeypatch.setattr(cipr.session, "get", flaky_get)

        with pytest.raises(RuntimeError, match="Failed to fetch"):
            fetch_and_save_http_source(cipr, "google_cloud", cipr.sources["google_cloud"])
        assert not (tmp_path / "google-cloud.json").exists()

    def test_unknown_source_key_is_failure_not_crash(self, crawler: CloudIPRanges) -> None:
        """The sources argument is a filter — unknown names select nothing."""
        assert crawler.fetch_all({"no_such_provider"}) is True
        assert crawler.statistics == {}
        assert not (crawler.output_dir / "no-such-provider.json").exists()

    def test_failure_then_recovery_between_runs(self, crawler: CloudIPRanges, monkeypatch: pytest.MonkeyPatch) -> None:
        get = Mock(side_effect=requests.exceptions.Timeout("t"))
        monkeypatch.setattr(crawler.session, "get", get)
        assert crawler.fetch_all({"google_cloud"}) is False

        get.side_effect = None
        get.return_value = _ok_response(json_data=_google_payload())
        assert crawler.fetch_all({"google_cloud"}) is True
        assert crawler.statistics["google_cloud"] == {"ipv4": 1, "ipv6": 0}
        assert json.loads((crawler.output_dir / "google-cloud.json").read_text())["ipv4"] == ["8.8.4.0/24"]


class TestCycleTLSFaults:
    @pytest.fixture(autouse=True)
    def no_sleep(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cycletls_mod.time, "sleep", lambda _s: None)

    def _client(self, side_effect=None, statuses=None) -> Mock:
        client = Mock()
        if side_effect is not None:
            client.get.side_effect = side_effect
        else:
            responses = []
            for s in statuses or []:
                r = Mock()
                r.status_code = s
                r.headers = {}
                responses.append(r)
            client.get.side_effect = responses
        return client

    def test_retryable_status_retried_until_success(self) -> None:
        client = self._client(statuses=[503, 503, 200])
        resp = cycletls_mod._fetch_with_retry(client, "https://x", "src")
        assert resp.status_code == 200
        assert client.get.call_count == 3

    def test_timeout_retries_then_raises(self) -> None:
        client = self._client(side_effect=cycletls_mod.Timeout("slow"))
        with pytest.raises(cycletls_mod.Timeout):
            cycletls_mod._fetch_with_retry(client, "https://x", "src")
        assert client.get.call_count == cycletls_mod._MAX_RETRIES

    def test_connection_error_recovered_on_retry(self) -> None:
        ok = Mock()
        ok.status_code = 200
        client = self._client(side_effect=[cycletls_mod.ConnectionError("reset"), ok])
        assert cycletls_mod._fetch_with_retry(client, "https://x", "src") is ok

    def test_non_retryable_status_fails_immediately(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """404 must not be retried — it's deterministic, not transient."""
        client = self._client(statuses=[404])
        monkeypatch.setattr(cycletls_mod, "CycleTLS", lambda: client)
        cipr = CloudIPRanges({"json"})
        cipr.output_dir = tmp_path
        cipr.sources = {"zscaler": ["https://example.com/missing"]}

        with pytest.raises(RuntimeError, match="Failed to fetch"):
            cycletls_mod.fetch_and_save_cycletls_source(cipr, "zscaler", cipr.sources["zscaler"])
        assert client.get.call_count == 1

    def test_client_closed_on_success_and_failure(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        closed = []

        class FakeClient:
            def __init__(self, resp):
                self._resp = resp

            def get(self, url, timeout=None):
                return self._resp

            def close(self):
                closed.append(True)

        ok = Mock()
        ok.status_code = 200
        ok.headers = {}
        ok.json.return_value = _google_payload()

        monkeypatch.setattr(cycletls_mod, "CycleTLS", lambda: FakeClient(ok))
        cipr = CloudIPRanges({"json"})
        cipr.output_dir = tmp_path
        cipr.sources = {"google_cloud": ["https://example.com/p.json"]}

        cycletls_mod.fetch_and_save_cycletls_source(cipr, "google_cloud", cipr.sources["google_cloud"])
        assert closed, "client must be closed after successful fetch"

        closed.clear()
        boom = Mock()
        boom.status_code = 403
        monkeypatch.setattr(cycletls_mod, "CycleTLS", lambda: FakeClient(boom))
        with pytest.raises(RuntimeError):
            cycletls_mod.fetch_and_save_cycletls_source(cipr, "google_cloud", cipr.sources["google_cloud"])
        assert closed, "client must be closed even when the fetch fails"


class TestAsnSourceFaults:
    @pytest.fixture()
    def crawler(self, tmp_path: Path) -> CloudIPRanges:
        cipr = CloudIPRanges({"json"})
        cipr.output_dir = tmp_path
        cipr.sources = {"testasn": ["AS12345"]}
        return cipr

    def test_ripestat_failure_falls_back_to_hackertarget(self, crawler: CloudIPRanges, monkeypatch: pytest.MonkeyPatch) -> None:
        import sources.asn as asn_mod

        monkeypatch.setattr(crawler, "ripestat_fetch", Mock(side_effect=requests.exceptions.ConnectionError("ripestat down")))

        ht = _ok_response(text='"AS","12345","ISP"\n12345, 8.8.8.0/24\n')
        monkeypatch.setattr(crawler.session, "get", Mock(return_value=ht))

        data = asn_mod.fetch_and_save_asn_source(crawler, "testasn", crawler.sources["testasn"])
        assert data["ipv4"] == ["8.8.8.0/24"]
        assert data["method"] == "asn_lookup"
        assert any("hackertarget" in u for u in data["source"])

    def test_both_lookups_failing_fails_source(self, crawler: CloudIPRanges, monkeypatch: pytest.MonkeyPatch) -> None:
        import sources.asn as asn_mod

        monkeypatch.setattr(crawler, "ripestat_fetch", Mock(side_effect=requests.exceptions.Timeout("t")))
        monkeypatch.setattr(crawler.session, "get", Mock(side_effect=requests.exceptions.ConnectionError("c")))

        with pytest.raises(RuntimeError, match="Failed to parse"):
            asn_mod.fetch_and_save_asn_source(crawler, "testasn", crawler.sources["testasn"])

    def test_malformed_ripestat_body_fails_instead_of_silent_empty(self, crawler: CloudIPRanges, monkeypatch: pytest.MonkeyPatch) -> None:
        """HTTP 200 with an unparseable body must surface as failure, not empty output."""
        import sources.asn as asn_mod

        bad = _ok_response()
        bad.json.side_effect = ValueError("garbage")
        monkeypatch.setattr(crawler, "ripestat_fetch", Mock(return_value=("https://r", bad)))
        monkeypatch.setattr(crawler.session, "get", Mock(return_value=_ok_response(text="")))

        with pytest.raises(RuntimeError, match="Failed to parse"):
            asn_mod.fetch_and_save_asn_source(crawler, "testasn", crawler.sources["testasn"])

    def test_radb_failure_still_uses_plain_asn(self, crawler: CloudIPRanges, monkeypatch: pytest.MonkeyPatch) -> None:
        import sources.asn as asn_mod

        monkeypatch.setattr(asn_mod, "radb_resolve_as_set", Mock(side_effect=RuntimeError("whois down")))

        resp = _ok_response(
            json_data={
                "data": {"queried_at": "t", "prefixes": [{"prefix": "8.8.8.0/24"}]},
            }
        )
        monkeypatch.setattr(crawler, "ripestat_fetch", Mock(return_value=("https://ripe", resp)))

        data = asn_mod.fetch_and_save_asn_source(crawler, "testasn", ["RADB::AS-SET", "AS12345"])
        assert data["ipv4"] == ["8.8.8.0/24"]

    def test_no_resolvable_asns_fails(self, crawler: CloudIPRanges, monkeypatch: pytest.MonkeyPatch) -> None:
        import sources.asn as asn_mod

        monkeypatch.setattr(asn_mod, "radb_resolve_as_set", Mock(return_value=set()))
        with pytest.raises(RuntimeError, match="no ASNs"):
            asn_mod.fetch_and_save_asn_source(crawler, "testasn", ["RADB::EMPTY", "not-an-asn"])


class TestNegativePaths:
    def test_empty_ipv4_and_ipv6_payload_rejected(self) -> None:
        cipr = CloudIPRanges({"json"})
        with pytest.raises(RuntimeError, match="Failed to parse"):
            cipr._normalize_transformed_data({"ipv4": [], "ipv6": []}, "x")

    def test_all_private_ranges_rejected(self) -> None:
        """A transform that only produced private space must not publish."""
        cipr = CloudIPRanges({"json"})
        with pytest.raises(RuntimeError, match="Failed to parse"):
            cipr._normalize_transformed_data({"ipv4": ["10.0.0.0/8", "192.168.0.0/16"], "ipv6": []}, "x")

    def test_missing_transform_module_propagates_as_failure(self, tmp_path: Path) -> None:
        cipr = CloudIPRanges({"json"})
        cipr.output_dir = tmp_path
        cipr.sources = {"nonexistent_provider": ["https://example.com/x"]}
        assert cipr.fetch_all({"nonexistent_provider"}) is False
        assert "nonexistent_provider" not in cipr.statistics

    def test_max_delta_empty_old_to_nonempty_new_is_growth(self) -> None:
        cipr = CloudIPRanges({"json"})
        cipr._enforce_max_delta({"ipv4": [], "ipv6": []}, {"ipv4": ["8.8.8.0/24"], "ipv6": []}, max_ratio=0.1, source_key="x")

    def test_duplicate_cidrs_in_output_are_deduped(self, tmp_path: Path) -> None:
        cipr = CloudIPRanges({"json"})
        data = cipr._normalize_transformed_data({"ipv4": ["8.8.8.0/24", "8.8.8.0/24", "8.8.8.0/25", "8.8.8.128/25"], "ipv6": []}, "x")
        assert sorted(data["ipv4"]) == ["8.8.8.0/24", "8.8.8.0/25", "8.8.8.128/25"]


class TestAtomicWrites:
    def test_failed_write_leaves_no_partial_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cipr = CloudIPRanges({"json"})
        cipr.output_dir = tmp_path

        def exploding_dump(*args: Any, **kwargs: Any) -> None:
            raise OSError("disk full mid-write")

        monkeypatch.setattr(json, "dump", exploding_dump)
        with pytest.raises(OSError):
            cipr._save_json({"ipv4": [], "ipv6": []}, "p.json")

        assert not (tmp_path / "p.json").exists()
        assert not list(tmp_path.glob("*.tmp")), "temp file must be cleaned up"

    def test_failed_write_preserves_existing_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cipr = CloudIPRanges({"json"})
        cipr.output_dir = tmp_path
        target = tmp_path / "p.json"
        original = b'{"ipv4": ["8.8.8.0/24"], "ipv6": []}'
        target.write_bytes(original)

        monkeypatch.setattr(json, "dump", Mock(side_effect=OSError("disk full")))
        with pytest.raises(OSError):
            cipr._save_json({"ipv4": ["1.2.3.0/24"], "ipv6": []}, "p.json")

        assert target.read_bytes() == original
