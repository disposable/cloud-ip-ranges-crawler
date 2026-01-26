"""Provider-specific transform tests."""

import pytest
from io import BytesIO
from zipfile import ZipFile

from tests.unit.conftest import FakeResponse, SAMPLES_DIR, _load_raw, _has_valid_ipv4, _has_valid_ipv6


def test_cloudflare_transform(cipr) -> None:
    r_v4 = _load_raw(SAMPLES_DIR / "cloudflare_0.raw")
    r_v6 = _load_raw(SAMPLES_DIR / "cloudflare_1.raw")
    res = cipr._transform_response([r_v4, r_v6], "cloudflare", is_asn=False)
    assert res["provider"] == "Cloudflare"
    assert _has_valid_ipv4(res)
    assert _has_valid_ipv6(res)


def test_google_cloud_transform_has_details(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "google_cloud_0.raw")
    res = cipr._transform_response([r], "google_cloud", is_asn=False)
    assert res["provider"] == "Google Cloud"
    assert _has_valid_ipv4(res)
    assert _has_valid_ipv6(res)
    assert res.get("details_ipv4") and {"address", "service", "scope"}.issubset(res["details_ipv4"][0].keys())
    assert res["details_ipv6"] and {"address", "service", "scope"}.issubset(res["details_ipv6"][0].keys())


def test_google_bot_transform(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "google_bot_0.raw")
    res = cipr._transform_response([r], "google_bot", is_asn=False)
    assert res["provider"] == "Google Bot"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_bing_bot_transform(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "bing_bot_0.raw")
    res = cipr._transform_response([r], "bing_bot", is_asn=False)
    assert res["provider"] == "Bing Bot"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_openai_transform(cipr) -> None:
    r0 = _load_raw(SAMPLES_DIR / "openai_0.raw")
    r1 = _load_raw(SAMPLES_DIR / "openai_1.raw")
    res = cipr._transform_response([r0, r1], "openai", is_asn=False)
    assert res["provider"] == "Openai"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_perplexity_transform(cipr) -> None:
    r0 = _load_raw(SAMPLES_DIR / "perplexity_0.raw")
    r1 = _load_raw(SAMPLES_DIR / "perplexity_1.raw")
    res = cipr._transform_response([r0, r1], "perplexity", is_asn=False)
    assert res["provider"] == "Perplexity"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_github_transform_limits_to_hooks_and_web(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "github_0.raw")
    res = cipr._transform_response([r], "github", is_asn=False)
    assert _has_valid_ipv4(res)
    cats_v4 = {d.get("category") for d in res.get("details_ipv4", [])}
    cats_v6 = {d.get("category") for d in res.get("details_ipv6", [])}
    assert cats_v4.issubset({"hooks", "web"})
    assert cats_v6.issubset({"hooks", "web"})


def test_zscaler_transform_merges_required_and_recommended(cipr) -> None:
    r_required = _load_raw(SAMPLES_DIR / "zscaler_0.raw")
    r_recommended = _load_raw(SAMPLES_DIR / "zscaler_1.raw")
    res = cipr._transform_response([r_required, r_recommended], "zscaler", is_asn=False)
    assert res["provider"] == "Zscaler"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_fastly_transform_basic(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "fastly_0.raw")
    res = cipr._transform_response([r], "fastly", is_asn=False)
    assert res["provider"] == "Fastly"
    assert isinstance(res["ipv4"], list)
    assert isinstance(res["ipv6"], list)


def test_telegram_transform_csv_like(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "telegram_0.raw")
    res = cipr._transform_response([r], "telegram", is_asn=False)
    assert res["provider"] == "Telegram"
    assert _has_valid_ipv4(res)


def test_linode_transform_csv(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "linode_0.raw")
    res = cipr._transform_response([r], "linode", is_asn=False)
    assert res["provider"] == "Linode"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_starlink_transform_csv(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "starlink_0.raw")
    res = cipr._transform_response([r], "starlink", is_asn=False)
    assert res["provider"] == "Starlink"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_digitalocean_transform_csv(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "digitalocean_0.raw")
    res = cipr._transform_response([r], "digitalocean", is_asn=False)
    assert res["provider"] == "Digitalocean"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_ahrefs_transform_json(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "ahrefs_0.raw")
    res = cipr._transform_response([r], "ahrefs", is_asn=False)
    assert res["provider"] == "Ahrefs"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_aws_transform_json(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "aws_0.raw")
    res = cipr._transform_response([r], "aws", is_asn=False)
    assert res["provider"] == "Aws"
    assert _has_valid_ipv4(res)
    assert _has_valid_ipv6(res)
    assert "details_ipv4" in res and "details_ipv6" in res


def test_oracle_cloud_transform_json_with_details(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "oracle_cloud_0.raw")
    res = cipr._transform_response([r], "oracle_cloud", is_asn=False)
    assert res["provider"] == "Oracle Cloud"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_vultr_transform_json_with_details(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "vultr_0.raw")
    res = cipr._transform_response([r], "vultr", is_asn=False)
    assert res["provider"] == "Vultr"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_akamai_transform_zip_content(cipr) -> None:
    # Build an in-memory zip matching expected filenames with both IPv4 and IPv6 CIDRs
    bio = BytesIO()
    with ZipFile(bio, "w") as zf:
        zf.writestr("akamai_ipv4_CIDRs.txt", "1.2.3.0/24\n5.6.7.0/24\n")
        zf.writestr("akamai_ipv6_CIDRs.txt", "2606:4700::/32\n2606:4700:1::/48\n")
    r = FakeResponse(content=bio.getvalue())
    res = cipr._transform_response([r], "akamai", is_asn=False)
    assert res["provider"] == "Akamai"
    assert isinstance(res["ipv4"], list)
    assert isinstance(res["ipv6"], list)


def test_microsoft_azure_transform_with_mocked_downloads(cipr, monkeypatch: pytest.MonkeyPatch) -> None:
    html_page = FakeResponse(text='<a href="https://download.microsoft.com/ServiceTags_Public.json">download</a>')

    def fake_get(url: str, timeout: int = 10):
        if url.endswith("ServiceTags_Public.json"):
            return FakeResponse(json_data={"values": [{"properties": {"addressPrefixes": ["13.68.0.0/18", "2603:1040::/48"], "systemService": "Azure"}}]})
        return html_page

    monkeypatch.setattr(cipr.session, "get", fake_get)
    res = cipr._transform_response([html_page], "microsoft_azure", is_asn=False)
    assert res["provider"] == "Microsoft Azure"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)
    assert res.get("details_ipv4") is not None


def test_whatsapp_transform_with_mocked_zip(cipr, monkeypatch: pytest.MonkeyPatch) -> None:
    html_page = FakeResponse(text='<a href="https://example.fbcdn.net/sample.zip">zip</a>')

    def build_zip_bytes() -> bytes:
        bio = BytesIO()
        with ZipFile(bio, "w") as zf:
            zf.writestr("whatsapp.txt", "31.13.0.0/16\n2606:4700::/32\n")
        return bio.getvalue()

    def fake_get(url: str, timeout: int = 10):
        if url.endswith("sample.zip"):
            return FakeResponse(content=build_zip_bytes())
        return html_page

    monkeypatch.setattr(cipr.session, "get", fake_get)
    res = cipr._transform_response([html_page], "whatsapp", is_asn=False)
    assert res["provider"] == "Whatsapp"
    assert any("." in ip for ip in res["ipv4"])  # entries parsed from zip


def test_zendesk_transform_parses_ingress_and_egress(cipr) -> None:
    r = FakeResponse(json_data={
        "ips": {
            "ingress": {"all": ["216.198.0.0/18"], "specific": ["104.18.248.37/32"]},
            "egress": {"all": ["192.161.156.0/24"], "specific": ["104.18.248.37/32"]},
        }
    })
    res = cipr._transform_response([r], "zendesk", is_asn=False)
    assert res["provider"] == "Zendesk"
    assert "216.198.0.0/18" in res["ipv4"]
    assert "104.18.248.37/32" in res["ipv4"]


def test_okta_transform_extracts_nested_ranges(cipr) -> None:
    r = FakeResponse(json_data={
        "last_updated": "2026-01-02T00:00:00Z",
        "ranges": [
            {"service": "okta", "cidrs": ["4.4.4.0/24", "2606:4700::/32"]}
        ]
    })
    res = cipr._transform_response([r], "okta", is_asn=False)
    assert res["provider"] == "Okta"
    assert "4.4.4.0/24" in res["ipv4"]
    assert "2606:4700::/32" in res["ipv6"]


def test_datadog_transform_extracts_ranges_by_heuristics(cipr) -> None:
    r = FakeResponse(json_data={
        "modified": "2026-01-03T00:00:00Z",
        "agents": {"prefixes_ipv4": ["4.4.4.0/24"], "prefixes_ipv6": ["2606:4700::/32"]},
    })
    res = cipr._transform_response([r], "datadog", is_asn=False)
    assert res["provider"] == "Datadog"
    assert "4.4.4.0/24" in res["ipv4"]
    assert "2606:4700::/32" in res["ipv6"]


def test_atlassian_transform_parses_items_list(cipr) -> None:
    r = FakeResponse(json_data={
        "creationDate": "2026-01-04T00:00:00Z",
        "items": [
            {"cidr": "5.5.5.0/24"},
            {"cidr": "2606:4700::/32"},
        ]
    })
    res = cipr._transform_response([r], "atlassian", is_asn=False)
    assert res["provider"] == "Atlassian"
    assert "5.5.5.0/24" in res["ipv4"]
    assert "2606:4700::/32" in res["ipv6"]


def test_vercel_rdap_transform_discovers_org_nets(cipr, monkeypatch: pytest.MonkeyPatch) -> None:
    rdap_seed = FakeResponse(json_data={
        "entities": [
            {"handle": "ZEITI", "roles": ["registrant"]},
            {"handle": "VERCEL", "roles": ["administrative"]},
        ]
    })
    org_xml = (
        "<?xml version='1.0'?>"
        "<org xmlns='https://www.arin.net/whoisrws/core/v1'>"
        "<updateDate>2025-12-24T07:44:44-05:00</updateDate>"
        "</org>"
    )
    nets_xml = (
        "<?xml version='1.0'?>"
        "<nets xmlns='https://www.arin.net/whoisrws/core/v1'>"
        "<netRef startAddress='76.76.21.0' endAddress='76.76.21.255' handle='NET-76-76-21-0-1' name='VERCEL-01'>"
        "https://whois.arin.net/rest/net/NET-76-76-21-0-1"
        "</netRef>"
        "<netRef startAddress='198.169.1.0' endAddress='198.169.1.255' handle='NET-198-169-1-0-1' name='VERCEL-02'>"
        "https://whois.arin.net/rest/net/NET-198-169-1-0-1"
        "</netRef>"
        "</nets>"
    )

    def fake_get(url: str, timeout: int = 10):
        if url.startswith("https://rdap.arin.net/registry/ip/"):
            return rdap_seed
        if url.endswith("/rest/org/ZEITI"):
            return FakeResponse(text=org_xml)
        if url.endswith("/rest/org/ZEITI/nets"):
            return FakeResponse(text=nets_xml)
        return FakeResponse(text="")

    monkeypatch.setattr(cipr.session, "get", fake_get)
    res = cipr._transform_response([rdap_seed], "vercel", is_asn=False)
    assert res["provider"] == "Vercel"
    assert "76.76.21.0/24" in res["ipv4"]
    assert "198.169.1.0/24" in res["ipv4"]
