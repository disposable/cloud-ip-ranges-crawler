"""Additional coverage-oriented tests for CloudIPRanges."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import src.cloud_ip_ranges as cloud_module
from src.cloud_ip_ranges import CloudIPRanges


def _sample_transformed(source: Any) -> dict[str, Any]:
    return {
        "provider": "Test",
        "provider_id": "test",
        "method": "published_list",
        "coverage_notes": "",
        "generated_at": "2024-01-01T00:00:00",
        "source_updated_at": None,
        "source": source,
        "last_update": "2024-01-01T00:00:00",
        "ipv4": ["198.51.100.0/24"],
        "ipv6": [],
        "details_ipv4": [],
        "details_ipv6": [],
        "source_http": [],
    }


def test_normalize_transformed_data_raises_when_no_valid_ips() -> None:
    crawler = CloudIPRanges({"json"})
    data = {
        "ipv4": ["10.0.0.0/8", "invalid"],
        "ipv6": ["::"],
        "details_ipv4": [{"address": None}],
        "details_ipv6": [{"address": ""}],
    }

    with pytest.raises(RuntimeError, match="Failed to parse broken"):
        crawler._normalize_transformed_data(data, "broken")


def test_fetch_and_save_routes_seed_cidr(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"seed": ["192.0.2.0/24"]}

    called = {}

    def fake_seed(cipr, source_key: str, url):
        called["seed"] = True
        return _sample_transformed(url[0])

    monkeypatch.setattr(cloud_module, "fetch_and_save_seed_cidr_source", fake_seed)
    monkeypatch.setattr(crawler, "_audit_transformed_data", lambda *_, **__: None)
    monkeypatch.setattr(crawler, "_save_result", lambda data, key: (len(data["ipv4"]), len(data["ipv6"])))

    res = crawler._fetch_and_save("seed")
    assert res == (1, 0)
    assert called["seed"]


def test_fetch_and_save_routes_http_when_seed_detection_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"http": ["198.51.100.bad/24"]}

    called = {}

    def fake_http(cipr, source_key: str, url):
        called["http"] = True
        return _sample_transformed(url[0])

    monkeypatch.setattr(cloud_module, "fetch_and_save_http_source", fake_http)
    monkeypatch.setattr(crawler, "_audit_transformed_data", lambda *_, **__: None)
    monkeypatch.setattr(crawler, "_save_result", lambda data, key: (len(data["ipv4"]), len(data["ipv6"])))

    res = crawler._fetch_and_save("http")
    assert res == (1, 0)
    assert called["http"]


def test_fetch_and_save_routes_asn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"asn": ["AS65000"]}

    called = {}

    def fake_asn(cipr, source_key: str, url):
        called["asn"] = True
        return _sample_transformed(url[0])

    monkeypatch.setattr(cloud_module, "fetch_and_save_asn_source", fake_asn)
    monkeypatch.setattr(crawler, "_audit_transformed_data", lambda *_, **__: None)
    monkeypatch.setattr(crawler, "_save_result", lambda data, key: (len(data["ipv4"]), len(data["ipv6"])))

    res = crawler._fetch_and_save("asn")
    assert res == (1, 0)
    assert called["asn"]


def test_fetch_and_save_only_if_changed_skips_save(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    crawler = CloudIPRanges({"json"}, only_if_changed=True, max_delta_ratio=0.1)
    crawler.base_url = tmp_path
    crawler.sources = {"dup": ["https://example.com/data.json"]}

    payload = _sample_transformed(["https://example.com/data.json"])
    existing_path = tmp_path / "dup.json"
    existing_path.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(cloud_module, "fetch_and_save_http_source", lambda *args, **kwargs: _sample_transformed(["https://example.com/data.json"]))
    monkeypatch.setattr(crawler, "_audit_transformed_data", lambda *_, **__: None)

    enforce_calls: dict[str, int] = {"count": 0}

    def fake_enforce(*args, **kwargs):
        enforce_calls["count"] += 1

    monkeypatch.setattr(crawler, "_enforce_max_delta", fake_enforce)

    def fail_save(*_args, **_kwargs):
        raise AssertionError("_save_result should not be called when data is unchanged")

    monkeypatch.setattr(crawler, "_save_result", fail_save)

    res = crawler._fetch_and_save("dup")
    assert res == (1, 0)
    assert enforce_calls["count"] == 1


def test_audit_transformed_data_detects_ipv6_default_route() -> None:
    crawler = CloudIPRanges({"json"})
    data = _sample_transformed("source")
    data["ipv6"] = ["::/0"]

    with pytest.raises(RuntimeError, match="default route"):
        crawler._audit_transformed_data(data, "test")


def test_enforce_max_delta_raises_when_ratio_exceeded() -> None:
    crawler = CloudIPRanges({"json"})
    old = {"ipv4": ["198.51.100.0/24"], "ipv6": []}
    new = {"ipv4": ["198.51.100.0/24", "203.0.113.0/24"], "ipv6": []}

    with pytest.raises(RuntimeError, match="Delta check failed"):
        crawler._enforce_max_delta(old, new, max_ratio=0.2, source_key="test")


def test_save_result_unknown_format_raises(tmp_path: Path) -> None:
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.output_formats = {"json", "yaml"}

    with pytest.raises(ValueError, match="Unknown output format"):
        crawler._save_result(_sample_transformed(["https://example.com"]), "weird")


def test_fetch_all_handles_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    crawler = CloudIPRanges({"json"})
    crawler.sources = {"good": ["url"], "bad": ["url"]}

    calls: list[str] = []

    def fake_fetch(source_key: str):
        calls.append(source_key)
        if source_key == "bad":
            raise RuntimeError("boom")
        return (2, 1)

    monkeypatch.setattr(crawler, "_fetch_and_save", fake_fetch)

    result = crawler.fetch_all()
    assert result is False
    assert crawler.statistics["good"] == {"ipv4": 2, "ipv6": 1}
    assert "bad" not in crawler.statistics
    assert calls == ["good", "bad"]


def test_fetch_all_propagates_outer_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    crawler = CloudIPRanges({"json"})
    monkeypatch.setattr(crawler, "sources", None)

    with pytest.raises(TypeError):
        crawler.fetch_all()


def test_fetch_all_writes_merged_outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    crawler = CloudIPRanges({"json", "csv", "txt"}, merge_all_providers=True)
    crawler.base_url = tmp_path
    crawler.sources = {"dummy": ["https://example.com"]}

    sample = _sample_transformed(["https://example.com"])
    sample["provider"] = "Dummy"
    sample["provider_id"] = "dummy"

    def fake_fetch(source_key: str):
        crawler._track_merged_outputs(sample)
        return len(sample["ipv4"]), len(sample["ipv6"])

    monkeypatch.setattr(crawler, "_fetch_and_save", fake_fetch)

    assert crawler.fetch_all({"dummy"}) is True

    merged_json_path = tmp_path / "all-providers.json"
    merged_csv_path = tmp_path / "all-providers.csv"
    merged_txt_path = tmp_path / "all-providers.txt"

    assert merged_json_path.exists()
    assert merged_csv_path.exists()
    assert merged_txt_path.exists()

    merged_json = json.loads(merged_json_path.read_text(encoding="utf-8"))
    assert merged_json["provider"] == "All Providers"
    assert merged_json["provider_count"] == 1
    assert merged_json["providers"][0]["provider_id"] == "dummy"
    assert merged_json["ipv4"] == sample["ipv4"]

    merged_csv = merged_csv_path.read_text(encoding="utf-8")
    assert "Type,Address" in merged_csv
    assert sample["ipv4"][0] in merged_csv

    merged_txt = merged_txt_path.read_text(encoding="utf-8")
    assert "# provider: All Providers" in merged_txt
    assert sample["ipv4"][0] in merged_txt


def test_fetch_all_skips_merged_outputs_when_disabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"dummy": ["https://example.com"]}

    sample = _sample_transformed(["https://example.com"])

    def fake_fetch(source_key: str):
        crawler._track_merged_outputs(sample)
        return len(sample["ipv4"]), len(sample["ipv6"])

    monkeypatch.setattr(crawler, "_fetch_and_save", fake_fetch)

    assert crawler.fetch_all({"dummy"}) is True

    assert not (tmp_path / "all-providers.json").exists()
    assert not (tmp_path / "all-providers.csv").exists()
    assert not (tmp_path / "all-providers.txt").exists()


def test_save_result_unknown_format_logs_first_file(tmp_path: Path) -> None:
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.output_formats = {"json", "txt", "unknown"}

    data = _sample_transformed(["https://example.com"])

    with pytest.raises(ValueError, match="Unknown output format"):
        crawler._save_result(data, "combo")


__all__ = [
    "test_normalize_transformed_data_raises_when_no_valid_ips",
    "test_fetch_and_save_routes_seed_cidr",
    "test_fetch_and_save_routes_http_when_seed_detection_fails",
    "test_fetch_and_save_routes_asn",
    "test_fetch_and_save_only_if_changed_skips_save",
    "test_audit_transformed_data_detects_ipv6_default_route",
    "test_enforce_max_delta_raises_when_ratio_exceeded",
    "test_save_result_unknown_format_raises",
    "test_fetch_all_handles_errors",
    "test_fetch_all_propagates_outer_errors",
    "test_save_result_unknown_format_logs_first_file",
    "test_fetch_all_writes_merged_outputs",
    "test_fetch_all_skips_merged_outputs_when_disabled",
]
