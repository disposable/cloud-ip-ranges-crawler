"""Core transform and CloudIPRanges behavior tests."""

import pytest
from pathlib import Path
import json
from typing import Any, Dict, List

from src.cloud_ip_ranges import CloudIPRanges
from src.transforms import get_transform

from tests.unit.conftest import FakeResponse, SAMPLES_DIR, _load_raw, _has_valid_ipv4, _has_valid_ipv6


def _transform_response(cipr: CloudIPRanges, response: List[Any], source_key: str, is_asn: bool) -> Dict[str, Any]:
    """Helper function to replace the removed _transform_response method for tests."""
    if is_asn:
        from src.sources.asn import transform_hackertarget

        transformed_data = transform_hackertarget(cipr, response, source_key)
    else:
        from src.transforms.registry import get_transform

        transform_fn = get_transform(source_key)
        transformed_data = transform_fn(cipr, response, source_key)

    return cipr._normalize_transformed_data(transformed_data, source_key)


def test_transform_method_selection() -> None:
    """Test transform method selection logic."""
    CloudIPRanges({"json"})

    # Transforms are loaded dynamically from src/transforms/<source>.py
    assert callable(get_transform("cloudflare"))
    assert callable(get_transform("aws"))
    assert callable(get_transform("github"))


def test_transform_response_asn_uses_hackertarget(cipr: CloudIPRanges) -> None:
    # Minimal hackertarget-like output
    r = FakeResponse(text="AS,IP\n1, 8.8.8.0/24\n2, 2606:4700::/32\n", url="https://api.hackertarget.com/aslookup/?q=AS123")
    res = _transform_response(cipr, [r], "hetzner", is_asn=True)
    assert res["method"] == "asn_lookup"
    assert "8.8.8.0/24" in res["ipv4"]
    assert "2606:4700::/32" in res["ipv6"]


def test_transform_response_apple_private_relay_csv(cipr: CloudIPRanges) -> None:
    r = _load_raw(SAMPLES_DIR / "apple_private_relay_0.raw")
    res = _transform_response(cipr, [r], "apple_private_relay", is_asn=False)
    assert res["provider"] == "Apple Private Relay"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_atlassian_transform_fallback_heuristic(cipr: CloudIPRanges) -> None:
    r = FakeResponse(
        json_data={
            "created": "2026-01-04T00:00:00Z",
            "nested": {"prefixes_ipv4": ["5.5.5.0/24"], "prefixes_ipv6": ["2606:4700::/32"]},
        }
    )
    res = _transform_response(cipr, [r], "atlassian", is_asn=False)
    assert res["source_updated_at"] == "2026-01-04T00:00:00Z"
    assert "5.5.5.0/24" in res["ipv4"]
    assert "2606:4700::/32" in res["ipv6"]


def test_oracle_cloud_transform_includes_ipv4_ipv6_lists(cipr: CloudIPRanges) -> None:
    r = FakeResponse(
        json_data={
            "regions": [
                {
                    "region": "region-1",
                    "cidrs": [{"cidr": "1.1.1.0/24"}],
                    "ipv4_cidrs": [{"cidr": "2.2.2.0/24"}],
                    "ipv6_cidrs": [{"cidr": "2606:4700::/32"}],
                }
            ]
        }
    )
    res = _transform_response(cipr, [r], "oracle_cloud", is_asn=False)
    assert "1.1.1.0/24" in res["ipv4"]
    assert "2.2.2.0/24" in res["ipv4"]
    assert "2606:4700::/32" in res["ipv6"]
    assert res.get("details_ipv4") and res.get("details_ipv6")


def test_save_result_writes_details_files(tmp_path: Path) -> None:
    crawler = CloudIPRanges({"json", "csv"})
    crawler.base_url = tmp_path
    data = {
        "provider": "Test",
        "provider_id": "test",
        "method": "published_list",
        "coverage_notes": "",
        "generated_at": "2024-01-01T00:00:00",
        "source_updated_at": "2024-01-01T00:00:00",
        "source": "https://example.com/test",
        "last_update": "2024-01-01T00:00:00",
        "ipv4": ["8.8.8.0/24"],
        "ipv6": ["2001:db8::/32"],
        "details_ipv4": [{"address": "8.8.8.0/24", "service": "svc"}],
        "details_ipv6": [{"address": "2001:db8::/32", "service": "svc"}],
    }

    crawler._save_result(data, "test")
    assert (tmp_path / "test-details.json").exists()
    assert (tmp_path / "test-details.csv").exists()


def test_add_env_statistics_writes_github_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    crawler = CloudIPRanges({"json"})
    crawler.statistics = {"a": {"ipv4": 1, "ipv6": 2}, "b": {"ipv4": 3, "ipv6": 4}}
    crawler._sources_with_changes = {"b"}

    out = tmp_path / "gh_out.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    crawler.add_env_statistics()

    txt = out.read_text(encoding="utf-8")
    assert "total_ipv4=4" in txt
    assert "total_ipv6=6" in txt
    assert "sources_updated=b" in txt
    assert "sources_count=1" in txt


def test_fetch_and_save_seed_cidr_source_vercel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"vercel": ["76.76.21.0/24"]}

    rdap = FakeResponse(json_data={"entities": [{"handle": "ZEITI", "roles": ["registrant"]}]})
    rdap.status_code = 200
    rdap.headers = {"content-type": "application/rdap+json"}

    org_xml = "<?xml version='1.0'?><org xmlns='https://www.arin.net/whoisrws/core/v1'><updateDate>2025-12-24T07:44:44-05:00</updateDate></org>"
    nets_xml = (
        "<?xml version='1.0'?>"
        "<nets xmlns='https://www.arin.net/whoisrws/core/v1'>"
        "<netRef startAddress='76.76.21.0' endAddress='76.76.21.255' handle='NET-76-76-21-0-1' name='VERCEL-01'>"
        "https://whois.arin.net/rest/net/NET-76-76-21-0-1"
        "</netRef>"
        "</nets>"
    )

    org_r = FakeResponse(text=org_xml)
    org_r.status_code = 200
    org_r.headers = {"content-type": "application/xml"}
    nets_r = FakeResponse(text=nets_xml)
    nets_r.status_code = 200
    nets_r.headers = {"content-type": "application/xml"}

    def fake_get(url: str, timeout: int = 10):
        if url.startswith("https://rdap.arin.net/registry/ip/"):
            return rdap
        if url.endswith("/rest/org/ZEITI"):
            return org_r
        if url.endswith("/rest/org/ZEITI/nets"):
            return nets_r
        return FakeResponse(text="")

    monkeypatch.setattr(crawler.session, "get", fake_get)
    res = crawler._fetch_and_save("vercel")
    assert res is not None
    assert (tmp_path / "vercel.json").exists()


def test_fetch_and_save_asn_source_merges_multiple_asns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"multi": ["AS1", "AS2"]}

    def fake_get(url: str, timeout: int = 10):
        if url.endswith("resource=AS1"):
            return FakeResponse(
                json_data={
                    "status": "ok",
                    "data": {"queried_at": "2026-01-01T00:00:00Z", "prefixes": [{"prefix": "1.1.1.0/24"}]},
                },
                url=url,
            )
        if url.endswith("resource=AS2"):
            return FakeResponse(
                json_data={
                    "status": "ok",
                    "data": {"queried_at": "2026-01-01T00:00:00Z", "prefixes": [{"prefix": "2606:4700::/32"}]},
                },
                url=url,
            )
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(crawler.session, "get", fake_get)
    res = crawler._fetch_and_save("multi")
    assert res is not None

    payload = json.loads((tmp_path / "multi.json").read_text(encoding="utf-8"))
    assert payload["method"] == "bgp_announced"
    assert "1.1.1.0/24" in payload["ipv4"]
    assert "2606:4700::/32" in payload["ipv6"]


def test_fetch_and_save_radb_as_set_expands_to_asns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from src.sources.asn import radb_whois_query

    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"fb": ["RADB::AS-FOO"]}

    radb_whois_query.cache_clear()

    def fake_radb_whois_query(query: str) -> str:
        if query == "AS-FOO":
            return "members: AS123 AS456\n"
        raise AssertionError(f"Unexpected RADB query: {query}")

    def fake_get(url: str, timeout: int = 10):
        if url.endswith("resource=AS123"):
            return FakeResponse(
                json_data={
                    "status": "ok",
                    "data": {"queried_at": "2026-01-01T00:00:00Z", "prefixes": [{"prefix": "2.2.2.0/24"}]},
                },
                url=url,
            )
        if url.endswith("resource=AS456"):
            return FakeResponse(
                json_data={
                    "status": "ok",
                    "data": {"queried_at": "2026-01-01T00:00:00Z", "prefixes": [{"prefix": "2606:4700::/32"}]},
                },
                url=url,
            )
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr("sources.asn.radb_whois_query", fake_radb_whois_query)
    monkeypatch.setattr(crawler.session, "get", fake_get)
    res = crawler._fetch_and_save("fb")
    assert res is not None

    payload = json.loads((tmp_path / "fb.json").read_text(encoding="utf-8"))
    assert "2.2.2.0/24" in payload["ipv4"]
    assert "2606:4700::/32" in payload["ipv6"]


def test_response_handling() -> None:
    """Test HTTP response handling."""
    # Test FakeResponse behavior
    response = FakeResponse(text="test content")
    assert response.text == "test content"

    response_json = FakeResponse(json_data={"key": "value"})
    assert response_json.json() == {"key": "value"}

    response_content = FakeResponse(content=b"binary content")
    assert response_content.content == b"binary content"


def test_transform_response_linode(cipr: CloudIPRanges) -> None:
    """Test Linode CSV transformation."""
    with open(SAMPLES_DIR / "linode_0.raw", "r") as f:
        content = f.read()
    response = FakeResponse(text=content)

    result = _transform_response(cipr, [response], "linode", is_asn=False)

    assert result["provider"] == "Linode"
    assert len(result["ipv4"]) > 0


def test_transform_response_google_cloud(cipr: CloudIPRanges) -> None:
    """Test Google Cloud JSON transformation."""
    with open(SAMPLES_DIR / "google_cloud_0.raw", "r") as f:
        content = f.read()
    response = FakeResponse(text=content)

    result = _transform_response(cipr, [response], "google_cloud", is_asn=False)

    assert result["provider"] == "Google Cloud"
    assert len(result["ipv4"]) > 0
    assert len(result["ipv6"]) > 0


def test_transform_response_google_bot(cipr: CloudIPRanges) -> None:
    """Test Google Bot JSON transformation."""
    with open(SAMPLES_DIR / "google_bot_0.raw", "r") as f:
        content = f.read()
    response = FakeResponse(text=content)

    result = _transform_response(cipr, [response], "google_bot", is_asn=False)

    assert result["provider"] == "Google Bot"
    assert len(result["ipv4"]) > 0
    assert len(result["ipv6"]) > 0


def test_transform_response_bing_bot(cipr: CloudIPRanges) -> None:
    """Test Bing Bot JSON transformation."""
    with open(SAMPLES_DIR / "bing_bot_0.raw", "r") as f:
        content = f.read()
    response = FakeResponse(text=content)

    result = _transform_response(cipr, [response], "bing_bot", is_asn=False)

    assert result["provider"] == "Bing Bot"
    assert len(result["ipv4"]) > 0


def test_transform_response_openai(cipr: CloudIPRanges) -> None:
    """Test OpenAI JSON transformation."""
    with open(SAMPLES_DIR / "openai_0.raw", "r") as f:
        content = f.read()
    response = FakeResponse(text=content)

    result = _transform_response(cipr, [response], "openai", is_asn=False)

    assert result["provider"] == "Openai"
    assert len(result["ipv4"]) > 0
    # Note: OpenAI only has IPv4 ranges in the sample


def test_transform_response_perplexity(cipr: CloudIPRanges) -> None:
    """Test Perplexity JSON transformation."""
    with open(SAMPLES_DIR / "perplexity_0.raw", "r") as f:
        content = f.read()
    response = FakeResponse(text=content)

    result = _transform_response(cipr, [response], "perplexity", is_asn=False)

    assert result["provider"] == "Perplexity"
    assert len(result["ipv4"]) > 0
    # Note: Perplexity only has IPv4 ranges in the sample


def test_transform_response_aws(cipr: CloudIPRanges) -> None:
    """Test AWS JSON transformation."""
    with open(SAMPLES_DIR / "aws_0.raw", "r") as f:
        content = f.read()
    response = FakeResponse(text=content)

    result = _transform_response(cipr, [response], "aws", is_asn=False)

    assert result["provider"] == "Aws"  # Note: actual provider name is "Aws"
    assert len(result["ipv4"]) > 0
    assert len(result["ipv6"]) > 0


def test_transform_response_cloudflare(cipr: CloudIPRanges) -> None:
    """Test Cloudflare text transformation."""
    with open(SAMPLES_DIR / "cloudflare_0.raw", "r") as f:
        ipv4_content = f.read()
    with open(SAMPLES_DIR / "cloudflare_1.raw", "r") as f:
        ipv6_content = f.read()

    response_ipv4 = FakeResponse(text=ipv4_content)
    response_ipv6 = FakeResponse(text=ipv6_content)

    result = _transform_response(cipr, [response_ipv4, response_ipv6], "cloudflare", is_asn=False)

    assert result["provider"] == "Cloudflare"
    assert len(result["ipv4"]) > 0
    assert len(result["ipv6"]) > 0


def test_transform_response_microsoft_azure(cipr: CloudIPRanges) -> None:
    """Test Microsoft Azure JSON transformation."""
    pytest.skip("Microsoft Azure sample file is incomplete due to SSL issues")


def test_ripestat_announced_prefixes_transform(cipr: CloudIPRanges) -> None:
    from src.sources.asn import transform_ripestat

    r = FakeResponse(
        json_data={
            "status": "ok",
            "data": {
                "queried_at": "2026-01-01T00:00:00Z",
                "prefixes": [
                    {"prefix": "1.2.3.0/24"},
                    {"prefix": "2606:4700::/32"},
                ],
            },
        },
        url="https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS12345",
    )
    res = transform_ripestat(cipr, [r], "test")
    assert res["method"] == "bgp_announced"
    assert "1.2.3.0/24" in res["ipv4"]
    assert "2606:4700::/32" in res["ipv6"]


def test_metadata_fields() -> None:
    """Test metadata field handling."""
    crawler = CloudIPRanges({"json"})

    result = crawler._transform_base("test", ["https://example.com"])

    # Check all required metadata fields
    required_fields = ["provider", "provider_id", "source", "method", "generated_at", "ipv4", "ipv6"]
    for field in required_fields:
        assert field in result

    # Check timestamp format (basic check that it's a string)
    assert isinstance(result["generated_at"], str)
    assert len(result["generated_at"]) > 0
