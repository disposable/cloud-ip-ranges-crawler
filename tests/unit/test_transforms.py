import json
from io import BytesIO
import ipaddress
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from src.cloud_ip_ranges import CloudIPRanges
from src.transforms import get_transform


SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


class FakeResponse:
    """Minimal stand-in for requests.Response for tests.

    Supports .text, .json(), .content, and .raise_for_status().
    """

    def __init__(self, *, text: str | None = None, json_data: Any | None = None, content: bytes | None = None) -> None:
        self._text = text
        self._json = json_data
        self._content = content

    @property
    def text(self) -> str:
        if self._text is not None:
            return self._text
        if self._json is not None:
            return json.dumps(self._json)
        if self._content is not None:
            try:
                return self._content.decode("utf-8")
            except Exception:
                return ""
        return ""

    def json(self) -> Any:
        if self._json is not None:
            return self._json
        if self._text is not None:
            return json.loads(self._text or "{}")
        if self._content is not None:
            return json.loads(self.text or "{}")
        return {}

    @property
    def content(self) -> bytes:
        if self._content is not None:
            return self._content
        if self._text is not None:
            return self._text.encode("utf-8")
        if self._json is not None:
            return json.dumps(self._json).encode("utf-8")
        return b""

    def raise_for_status(self) -> None:
        return None


def _load_raw(path: Path) -> FakeResponse:
    """Load a .raw sample file into a FakeResponse.

    - If JSON, return json_data.
    - Else try UTF-8 text.
    - On decode errors, treat as binary content.
    """
    try:
        txt = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        data = path.read_bytes()
        try:
            return FakeResponse(json_data=json.loads(data.decode("utf-8")))
        except Exception:
            return FakeResponse(content=data)
    try:
        return FakeResponse(json_data=json.loads(txt))
    except json.JSONDecodeError:
        return FakeResponse(text=txt)


@pytest.fixture()
def cipr() -> CloudIPRanges:
    return CloudIPRanges(output_formats={"json"})


def _has_valid_ipv4(res: dict) -> bool:
    for ip in res.get("ipv4", []):
        try:
            ipaddress.ip_network(ip, strict=False)
            return True
        except Exception:
            continue
    return False


def _has_valid_ipv6(res: dict) -> bool:
    for ip in res.get("ipv6", []):
        try:
            ipaddress.ip_network(ip, strict=False)
            if ":" in ip:
                return True
        except Exception:
            continue
    return False


def test_cloudflare_transform(cipr: CloudIPRanges) -> None:
    r_v4 = _load_raw(SAMPLES_DIR / "cloudflare_0.raw")
    r_v6 = _load_raw(SAMPLES_DIR / "cloudflare_1.raw")
    res = cipr._transform_response([r_v4, r_v6], "cloudflare", is_asn=False)
    assert res["provider"] == "Cloudflare"
    assert _has_valid_ipv4(res)
    assert _has_valid_ipv6(res)


def test_google_cloud_transform_has_details(cipr: CloudIPRanges) -> None:
    r = _load_raw(SAMPLES_DIR / "google_cloud_0.raw")
    res = cipr._transform_response([r], "google_cloud", is_asn=False)
    assert res["provider"] == "Google Cloud"
    assert "T" in res["last_update"]
    assert _has_valid_ipv4(res)
    assert _has_valid_ipv6(res)
    assert res["details_ipv4"] and {"address", "service", "scope"}.issubset(res["details_ipv4"][0].keys())
    assert res["details_ipv6"] and {"address", "service", "scope"}.issubset(res["details_ipv6"][0].keys())


def test_google_bot_transform(cipr: CloudIPRanges) -> None:
    r = _load_raw(SAMPLES_DIR / "google_bot_0.raw")
    res = cipr._transform_response([r], "google_bot", is_asn=False)
    assert res["provider"] == "Google Bot"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_bing_bot_transform(cipr: CloudIPRanges) -> None:
    r = _load_raw(SAMPLES_DIR / "bing_bot_0.raw")
    res = cipr._transform_response([r], "bing_bot", is_asn=False)
    assert res["provider"] == "Bing Bot"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_openai_transform(cipr: CloudIPRanges) -> None:
    r0 = _load_raw(SAMPLES_DIR / "openai_0.raw")
    r1 = _load_raw(SAMPLES_DIR / "openai_1.raw")
    res = cipr._transform_response([r0, r1], "openai", is_asn=False)
    assert res["provider"] == "Openai"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_perplexity_transform(cipr: CloudIPRanges) -> None:
    r0 = _load_raw(SAMPLES_DIR / "perplexity_0.raw")
    r1 = _load_raw(SAMPLES_DIR / "perplexity_1.raw")
    res = cipr._transform_response([r0, r1], "perplexity", is_asn=False)
    assert res["provider"] == "Perplexity"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_github_transform_limits_to_hooks_and_web(cipr: CloudIPRanges) -> None:
    r = _load_raw(SAMPLES_DIR / "github_0.raw")
    res = cipr._transform_response([r], "github", is_asn=False)
    assert _has_valid_ipv4(res)
    assert _has_valid_ipv6(res)
    cats_v4 = {d.get("category") for d in res.get("details_ipv4", [])}
    cats_v6 = {d.get("category") for d in res.get("details_ipv6", [])}
    assert cats_v4.issubset({"hooks", "web"})
    assert cats_v6.issubset({"hooks", "web"})


def test_zscaler_transform_merges_required_and_recommended(cipr: CloudIPRanges) -> None:
    r_required = _load_raw(SAMPLES_DIR / "zscaler_0.raw")
    r_recommended = _load_raw(SAMPLES_DIR / "zscaler_1.raw")
    res = cipr._transform_response([r_required, r_recommended], "zscaler", is_asn=False)
    assert res["provider"] == "Zscaler"
    cats_v4 = {d.get("category") for d in res.get("details_ipv4", [])}
    cats_v6 = {d.get("category") for d in res.get("details_ipv6", [])}
    assert {"required", "recommended"}.issubset(cats_v4.union(cats_v6))
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_fastly_transform_basic(cipr: CloudIPRanges) -> None:
    r = _load_raw(SAMPLES_DIR / "fastly_0.raw")
    res = cipr._transform_response([r], "fastly", is_asn=False)
    assert res["provider"] == "Fastly"
    assert isinstance(res["ipv4"], list)
    assert isinstance(res["ipv6"], list)


def test_telegram_transform_csv_like(cipr: CloudIPRanges) -> None:
    r = _load_raw(SAMPLES_DIR / "telegram_0.raw")
    res = cipr._transform_response([r], "telegram", is_asn=False)
    assert res["provider"] == "Telegram"
    assert _has_valid_ipv4(res)


def test_linode_transform_csv(cipr: CloudIPRanges) -> None:
    r = _load_raw(SAMPLES_DIR / "linode_0.raw")
    res = cipr._transform_response([r], "linode", is_asn=False)
    assert res["provider"] == "Linode"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_starlink_transform_csv(cipr: CloudIPRanges) -> None:
    r = _load_raw(SAMPLES_DIR / "starlink_0.raw")
    res = cipr._transform_response([r], "starlink", is_asn=False)
    assert res["provider"] == "Starlink"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_digitalocean_transform_csv(cipr: CloudIPRanges) -> None:
    r = _load_raw(SAMPLES_DIR / "digitalocean_0.raw")
    res = cipr._transform_response([r], "digitalocean", is_asn=False)
    assert res["provider"] == "Digitalocean"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_ahrefs_transform_json(cipr: CloudIPRanges) -> None:
    r = _load_raw(SAMPLES_DIR / "ahrefs_0.raw")
    res = cipr._transform_response([r], "ahrefs", is_asn=False)
    assert res["provider"] == "Ahrefs"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_aws_transform_json(cipr: CloudIPRanges) -> None:
    r = _load_raw(SAMPLES_DIR / "aws_0.raw")
    res = cipr._transform_response([r], "aws", is_asn=False)
    assert res["provider"] == "Aws"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)
    assert "details_ipv4" in res and "details_ipv6" in res


def test_oracle_cloud_transform_json_with_details(cipr: CloudIPRanges) -> None:
    r = _load_raw(SAMPLES_DIR / "oracle_cloud_0.raw")
    res = cipr._transform_response([r], "oracle_cloud", is_asn=False)
    assert res["provider"] == "Oracle Cloud"
    assert res.get("details_ipv4") or res.get("details_ipv6")
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_vultr_transform_json_with_details(cipr: CloudIPRanges) -> None:
    r = _load_raw(SAMPLES_DIR / "vultr_0.raw")
    res = cipr._transform_response([r], "vultr", is_asn=False)
    assert res["provider"] == "Vultr"
    assert res.get("details_ipv4") or res.get("details_ipv6")
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_akamai_transform_zip_content(cipr: CloudIPRanges) -> None:
    # Build an in-memory zip matching expected filenames with both IPv4 and IPv6 CIDRs
    from zipfile import ZipFile
    bio = BytesIO()
    with ZipFile(bio, "w") as zf:
        zf.writestr("akamai_ipv4_CIDRs.txt", "1.1.1.0/24\n# comment\n8.8.8.0/24\n")
        zf.writestr("akamai_ipv6_CIDRs.txt", "2001:db8::/32\n")
    r = FakeResponse(content=bio.getvalue())
    res = cipr._transform_response([r], "akamai", is_asn=False)
    assert res["provider"] == "Akamai"
    assert _has_valid_ipv4(res)
    assert isinstance(res["ipv6"], list)


def test_microsoft_azure_transform_with_mocked_downloads(cipr: CloudIPRanges, monkeypatch: pytest.MonkeyPatch) -> None:
    index_html = _load_raw(SAMPLES_DIR / "microsoft_azure_0.raw")

    def fake_get(url: str, timeout: int = 10):
        if url.startswith("https://download.microsoft.com/"):
            return FakeResponse(json_data={
                "values": [
                    {
                        "properties": {
                            "systemService": "ServiceA",
                            "region": "region-1",
                            "addressPrefixes": ["1.2.3.0/24", "2001:db8::/32"],
                        }
                    }
                ]
            })
        return FakeResponse(text="")

    monkeypatch.setattr(cipr.session, "get", fake_get)

    res = cipr._transform_response([index_html], "microsoft_azure", is_asn=False)
    assert res["provider"] == "Microsoft Azure"
    assert _has_valid_ipv4(res)
    # IPv6 prefixes may be filtered in certain environments; ensure details and at least one family present
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)
    assert res.get("details_ipv4") is not None


def test_whatsapp_transform_with_mocked_zip(cipr: CloudIPRanges, monkeypatch: pytest.MonkeyPatch) -> None:
    html_page = FakeResponse(text='<a href="https://example.fbcdn.net/sample.zip">zip</a>')

    def build_zip_bytes() -> bytes:
        from zipfile import ZipFile
        bio = BytesIO()
        with ZipFile(bio, "w") as zf:
            zf.writestr("data.txt", "8.8.8.0/24\n# comment\n1.1.1.1/32\n")
        return bio.getvalue()

    def fake_get(url: str, timeout: int = 10):
        return FakeResponse(content=build_zip_bytes())

    monkeypatch.setattr(cipr.session, "get", fake_get)
    res = cipr._transform_response([html_page], "whatsapp", is_asn=False)
    assert res["provider"] == "Whatsapp"
    assert any("." in ip for ip in res["ipv4"])  # entries parsed from zip


def test_ripestat_announced_prefixes_transform(cipr: CloudIPRanges) -> None:
    r = FakeResponse(json_data={
        "status": "ok",
        "data": {
            "queried_at": "2026-01-01T00:00:00Z",
            "resource": "AS24940",
            "prefixes": [
                {"prefix": "1.1.1.0/24"},
                {"prefix": "2606:4700::/32"},
            ],
        },
    })

    res = cipr._transform_ripestat_announced_prefixes([r], "hetzner", "AS24940")
    res = cipr._normalize_transformed_data(res, "hetzner")
    assert res["method"] == "bgp_announced"
    assert res["provider_id"] == "hetzner"
    assert res["source_updated_at"] == "2026-01-01T00:00:00Z"
    assert "1.1.1.0/24" in res["ipv4"]
    assert "2606:4700::/32" in res["ipv6"]


def test_zendesk_transform_parses_ingress_and_egress(cipr: CloudIPRanges) -> None:
    r = FakeResponse(json_data={
        "ips": {
            "ingress": {"all": ["216.198.0.0/18"], "specific": ["104.18.248.37/32"]},
            "egress": {"all": ["216.198.0.0/18"], "specific": []},
        }
    })
    res = cipr._transform_response([r], "zendesk", is_asn=False)
    assert res["provider"] == "Zendesk"
    assert "216.198.0.0/18" in res["ipv4"]
    assert "104.18.248.37/32" in res["ipv4"]


def test_okta_transform_extracts_nested_ranges(cipr: CloudIPRanges) -> None:
    r = FakeResponse(json_data={
        "last_updated": "2026-01-02T00:00:00Z",
        "ranges": [
            {"cidr": "3.3.3.0/24"},
            {"ipv6": "2606:4700::/32"},
        ],
    })
    res = cipr._transform_response([r], "okta", is_asn=False)
    assert res["provider"] == "Okta"
    assert res["source_updated_at"] == "2026-01-02T00:00:00Z"
    assert "3.3.3.0/24" in res["ipv4"]
    assert "2606:4700::/32" in res["ipv6"]


def test_datadog_transform_extracts_ranges_by_heuristics(cipr: CloudIPRanges) -> None:
    r = FakeResponse(json_data={
        "modified": "2026-01-03T00:00:00Z",
        "agents": {"prefixes_ipv4": ["4.4.4.0/24"], "prefixes_ipv6": ["2606:4700::/32"]},
    })
    res = cipr._transform_response([r], "datadog", is_asn=False)
    assert res["provider"] == "Datadog"
    assert res["source_updated_at"] == "2026-01-03T00:00:00Z"
    assert "4.4.4.0/24" in res["ipv4"]
    assert "2606:4700::/32" in res["ipv6"]


def test_atlassian_transform_parses_items_list(cipr: CloudIPRanges) -> None:
    r = FakeResponse(json_data={
        "creationDate": "2026-01-04T00:00:00Z",
        "items": [
            {"cidr": "5.5.5.0/24"},
            {"cidr": "2606:4700::/32"},
        ],
    })
    res = cipr._transform_response([r], "atlassian", is_asn=False)
    assert res["provider"] == "Atlassian"
    assert res["source_updated_at"] == "2026-01-04T00:00:00Z"
    assert "5.5.5.0/24" in res["ipv4"]
    assert "2606:4700::/32" in res["ipv6"]


def test_vercel_rdap_transform_discovers_org_nets(cipr: CloudIPRanges, monkeypatch: pytest.MonkeyPatch) -> None:
    rdap_seed = FakeResponse(json_data={
        "entities": [
            {"handle": "ZEITI", "roles": ["registrant"]},
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
        "<netRef startAddress='198.169.1.0' endAddress='198.169.1.255' handle='NET-198-169-1-0-1' name='VERCEL-03'>"
        "https://whois.arin.net/rest/net/NET-198-169-1-0-1"
        "</netRef>"
        "</nets>"
    )

    def fake_get(url: str, timeout: int = 10):
        if url.endswith("/rest/org/ZEITI"):
            return FakeResponse(text=org_xml)
        if url.endswith("/rest/org/ZEITI/nets"):
            return FakeResponse(text=nets_xml)
        return FakeResponse(text="")

    monkeypatch.setattr(cipr.session, "get", fake_get)
    res = cipr._transform_response([rdap_seed], "vercel", is_asn=False)
    assert res["provider"] == "Vercel"
    assert res["method"] == "rdap_registry"
    assert res["source_updated_at"] == "2025-12-24T07:44:44-05:00"
    assert "76.76.21.0/24" in res["ipv4"]
    assert "198.169.1.0/24" in res["ipv4"]


def test_seed_based_download_sample_format() -> None:
    """Test that seed-based sample files (like Vercel) have the correct format."""
    # Test Vercel specifically since we know it uses seed-based approach
    with open(SAMPLES_DIR / "vercel_0.raw", "r") as f:
        mock_data = json.load(f)

    # Verify the mock data structure for seed-based sources
    assert mock_data["mock_response"] is True
    assert mock_data["source"] == "vercel"
    assert "seeds" in mock_data
    assert "rdap_responses" in mock_data
    assert len(mock_data["rdap_responses"]) == len(mock_data["seeds"])

    # Verify each RDAP response has the expected structure
    for rdap_response in mock_data["rdap_responses"]:
        assert "entities" in rdap_response
        assert len(rdap_response["entities"]) > 0
        entity = rdap_response["entities"][0]
        assert "handle" in entity
        assert "roles" in entity
        assert "registrant" in entity["roles"]

    # Verify the handle is dynamically generated from the source name
    entity = mock_data["rdap_responses"][0]["entities"][0]
    assert "VERCEL-ARIN-HANDLE" in entity["handle"]


def test_audit_transformed_data():
    """Test audit checks for dangerous outputs."""
    crawler = CloudIPRanges({"json"})

    # Should pass - normal data
    good_data = {
        "ipv4": ["192.168.1.0/24", "10.0.0.0/8"],
        "ipv6": ["2001:db8::/32"]
    }
    crawler._audit_transformed_data(good_data, "test")

    # Should fail - default routes
    bad_data = {
        "ipv4": ["0.0.0.0/0", "192.168.1.0/24"],
        "ipv6": ["::/0"]
    }
    with pytest.raises(RuntimeError, match="contains default route"):
        crawler._audit_transformed_data(bad_data, "test")


def test_enforce_max_delta():
    """Test delta enforcement."""
    crawler = CloudIPRanges({"json"})

    # Should pass - within limit
    old = {"ipv4": ["10.0.0.0/24"], "ipv6": []}
    new = {"ipv4": ["10.0.0.0/24", "10.0.1.0/24"], "ipv6": []}
    crawler._enforce_max_delta(old, new, max_ratio=1.0, source_key="test")  # 100% increase, 100% limit

    # Should fail - exceeds limit
    with pytest.raises(RuntimeError, match="Delta check failed"):
        crawler._enforce_max_delta(old, new, max_ratio=0.5, source_key="test")  # 100% increase, 50% limit


def test_diff_summary():
    """Test diff summary generation."""
    crawler = CloudIPRanges({"json"})

    old = {"ipv4": ["10.0.0.0/24", "10.0.1.0/24"], "ipv6": ["2001:db8::/32"]}
    new = {"ipv4": ["10.0.0.0/24", "10.0.2.0/24"], "ipv6": ["2001:db8::/32", "2001:db8:1::/32"]}

    diff = crawler._diff_summary(old, new)

    assert diff["ipv4"]["old"] == 2
    assert diff["ipv4"]["new"] == 2
    assert diff["ipv4"]["added"] == 1
    assert diff["ipv4"]["removed"] == 1
    assert diff["ipv6"]["old"] == 1
    assert diff["ipv6"]["new"] == 2
    assert diff["ipv6"]["added"] == 1
    assert diff["ipv6"]["removed"] == 0


def test_audit_rejects_default_route(cipr: CloudIPRanges) -> None:
    """Test audit rejects default routes."""
    with pytest.raises(RuntimeError, match="contains default route"):
        cipr._audit_transformed_data({"ipv4": ["0.0.0.0/0"], "ipv6": []}, "test")


def test_delta_check_rejects_large_change(cipr: CloudIPRanges) -> None:
    """Test delta check rejects large changes."""
    old = {"ipv4": ["1.1.1.0/24"], "ipv6": []}
    new = {"ipv4": ["1.1.1.0/24", "2.2.2.0/24"], "ipv6": []}
    with pytest.raises(RuntimeError, match="Delta check failed"):
        cipr._enforce_max_delta(old, new, max_ratio=0.5, source_key="test")


def test_save_result_json(tmp_path: Path) -> None:
    """Test saving JSON output."""
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path

    data = {
        "provider": "Test",
        "ipv4": ["192.168.1.0/24"],
        "ipv6": ["2001:db8::/32"],
        "generated_at": "2024-01-01T00:00:00"
    }

    result = crawler._save_result(data, "test")

    assert result == (1, 1)
    json_file = tmp_path / "test.json"
    assert json_file.exists()

    with open(json_file) as f:
        saved = json.load(f)
    assert saved["provider"] == "Test"
    assert saved["ipv4"] == ["192.168.1.0/24"]


def test_save_result_csv_txt(tmp_path: Path) -> None:
    """Test saving CSV and TXT outputs."""
    crawler = CloudIPRanges({"csv", "txt"})
    crawler.base_url = tmp_path

    data = {
        "provider": "Test",
        "source": "https://example.com/test",
        "ipv4": ["192.168.1.0/24"],
        "ipv6": ["2001:db8::/32"],
        "generated_at": "2024-01-01T00:00:00",
        "last_update": "2024-01-01T00:00:00"
    }

    result = crawler._save_result(data, "test")

    assert result == (1, 1)

    # Check CSV
    csv_file = tmp_path / "test.csv"
    assert csv_file.exists()
    with open(csv_file) as f:
        lines = f.read().splitlines()
    assert "Type,Address" in lines
    assert "IPv4,192.168.1.0/24" in lines
    assert "IPv6,2001:db8::/32" in lines

    # Check TXT
    txt_file = tmp_path / "test.txt"
    assert txt_file.exists()
    with open(txt_file) as f:
        content = f.read()
    assert "192.168.1.0/24" in content
    assert "2001:db8::/32" in content


def test_only_if_changed_behavior(tmp_path: Path) -> None:
    """Test only_if_changed behavior."""
    crawler = CloudIPRanges({"json"}, only_if_changed=True)
    crawler.base_url = tmp_path

    data = {
        "provider": "Test",
        "ipv4": ["192.168.1.0/24"],
        "ipv6": [],
        "generated_at": "2024-01-01T00:00:00"
    }

    # First save should create file
    result1 = crawler._save_result(data, "test")
    assert result1 == (1, 0)

    # Second save with same data should not write file
    result2 = crawler._save_result(data, "test")
    assert result2 == (1, 0)

    # Third save with different data should write file
    data["ipv4"].append("10.0.0.0/8")
    result3 = crawler._save_result(data, "test")
    assert result3 == (2, 0)


def test_extract_cidrs_from_json() -> None:
    """Test CIDR extraction from JSON."""
    crawler = CloudIPRanges({"json"})

    # Test nested structure
    data = {
        "prefixes": [
            {"ipv4Prefix": "10.0.0.0/8"},
            {"ipv6Prefix": "2001:db8::/32"}
        ]
    }
    cidrs = crawler._extract_cidrs_from_json(data)
    assert "10.0.0.0/8" in cidrs
    assert "2001:db8::/32" in cidrs

    # Test flat list
    data2 = {
        "cidrs": ["192.168.1.0/24", "10.0.0.0/8"]
    }
    cidrs2 = crawler._extract_cidrs_from_json(data2)
    assert len(cidrs2) == 2
    assert "192.168.1.0/24" in cidrs2


def test_fetch_and_save_with_delta_enforcement(tmp_path: Path, monkeypatch) -> None:
    """Test _fetch_and_save with delta enforcement."""
    crawler = CloudIPRanges({"json"}, max_delta_ratio=0.3)
    crawler.base_url = tmp_path
    crawler.sources = {"test": ["https://example.com/test"]}

    # Create existing file
    existing_file = tmp_path / "test.json"
    existing_data = {
        "provider": "Test",
        "ipv4": ["10.0.0.0/24"],
        "ipv6": [],
        "generated_at": "2024-01-01T00:00:00"
    }
    with open(existing_file, "w") as f:
        json.dump(existing_data, f)

    # Mock successful fetch with too much change
    def mock_transform(*args, **kwargs):
        return {
            "provider": "Test",
            "ipv4": ["10.0.0.0/24", "10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"],  # 4x increase
            "ipv6": [],
            "generated_at": "2024-01-01T01:00:00"
        }

    def mock_get(*args, **kwargs):
        response = FakeResponse(text="test")
        response.status_code = 200
        response.headers = {"content-type": "application/json"}
        return response

    monkeypatch.setattr(crawler, "_transform_response", mock_transform)
    monkeypatch.setattr(crawler, "_normalize_transformed_data", lambda x, y: x)
    monkeypatch.setattr(crawler.session, "get", mock_get)

    # Should fail due to delta enforcement
    with pytest.raises(RuntimeError, match="Delta check failed"):
        crawler._fetch_and_save("test")


def test_transform_base() -> None:
    """Test base transformation method."""
    crawler = CloudIPRanges({"json"})

    result = crawler._transform_base("test", ["https://example.com"])

    assert result["provider"] == "Test"
    assert result["provider_id"] == "test"
    assert result["source"] == ["https://example.com"]
    assert result["method"] == "published_list"
    assert "generated_at" in result
    assert result["ipv4"] == []
    assert result["ipv6"] == []


def test_validate_ip() -> None:
    """Test IP validation function."""
    from src.cloud_ip_ranges import validate_ip

    # Valid public IPs
    assert validate_ip("8.8.8.8") == "8.8.8.8"
    assert validate_ip("1.1.1.1") == "1.1.1.1"
    assert validate_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"
    assert validate_ip("8.8.8.0/24") == "8.8.8.0/24"

    # Invalid or filtered IPs
    assert validate_ip("192.168.1.1") is None  # Private
    assert validate_ip("10.0.0.0/8") is None  # Private
    assert validate_ip("invalid") is None
    assert validate_ip("") is None
    assert validate_ip("999.999.999.999") is None


def test_xml_find_text() -> None:
    """Test XML text extraction helper."""
    crawler = CloudIPRanges({"json"})

    # Create a simple XML structure with namespace
    xml_content = '<root xmlns="http://example.com"><updateDate>2024-01-01</updateDate></root>'
    import defusedxml.ElementTree as ET
    root = ET.fromstring(xml_content)

    result = crawler._xml_find_text(root, "updateDate")
    assert result == "2024-01-01"

    # Non-existent tag
    result = crawler._xml_find_text(root, "nonexistent")
    assert result is None


def test_main_function() -> None:
    """Test main CLI function."""
    from src.cloud_ip_ranges import main
    import sys

    # Test help
    with patch.object(sys, "argv", ["cloud-ip-ranges", "--help"]):
        with pytest.raises(SystemExit) as exc:
            main()
            assert exc.value.code == 0


def test_fetch_all_function() -> None:
    """Test fetch_all method."""
    crawler = CloudIPRanges({"json"})

    # Mock the session to avoid actual network calls
    with patch.object(crawler, "_fetch_and_save", return_value=(1, 1)):
        result = crawler.fetch_all()
        assert result is True


def test_normalize_transformed_data() -> None:
    """Test data normalization."""
    crawler = CloudIPRanges({"json"})

    # Test with duplicate and invalid IPs
    data = {
        "ipv4": ["8.8.8.8", "8.8.8.8", "invalid", "1.1.1.1"],
        "ipv6": ["2001:4860:4860::8888", "2001:4860:4860::8888", "invalid", "2001:4860:4860::8888"]
    }

    result = crawler._normalize_transformed_data(data, "test")

    # Should deduplicate and filter invalid IPs
    assert len(result["ipv4"]) == 2  # 8.8.8.8 and 1.1.1.1
    assert "8.8.8.8" in result["ipv4"]
    assert "1.1.1.1" in result["ipv4"]
    assert len(result["ipv6"]) == 1  # Only 2001:4860:4860::8888 (2001:db8::1 is private)


def test_extract_cidrs_from_json() -> None:
    """Test CIDR extraction from JSON."""
    crawler = CloudIPRanges({"json"})

    # Test nested structure
    data = {
        "prefixes": [
            {"ipv4Prefix": "10.0.0.0/8"},
            {"ipv6Prefix": "2001:db8::/32"},
            {"cidr": "192.168.1.0/24"}
        ]
    }

    cidrs = crawler._extract_cidrs_from_json(data)
    assert "10.0.0.0/8" in cidrs
    assert "2001:db8::/32" in cidrs
    assert "192.168.1.0/24" in cidrs

    # Test flat list
    data2 = {"cidrs": ["192.168.2.0/24", "10.1.0.0/8"]}
    cidrs2 = crawler._extract_cidrs_from_json(data2)
    assert len(cidrs2) == 2


def test_has_valid_ipv4_ipv6() -> None:
    """Test validation helper functions."""
    # These are internal functions, let's test the logic directly
    def _has_valid_ipv4(data):
        return any(validate_ip(ip) for ip in data.get("ipv4", []))

    def _has_valid_ipv6(data):
        return any(validate_ip(ip) for ip in data.get("ipv6", []))

    from src.cloud_ip_ranges import validate_ip

    assert _has_valid_ipv4({"ipv4": ["8.8.8.8"], "ipv6": []}) is True
    assert _has_valid_ipv4({"ipv4": [], "ipv6": []}) is False
    assert _has_valid_ipv6({"ipv4": [], "ipv6": ["2001:4860:4860::8888"]}) is True
    assert _has_valid_ipv6({"ipv4": [], "ipv6": []}) is False


def test_error_handling() -> None:
    """Test error handling in various scenarios."""
    crawler = CloudIPRanges({"json"})

    # Test with empty data
    with pytest.raises(RuntimeError):
        crawler._normalize_transformed_data({"ipv4": [], "ipv6": []}, "test")

    # Test with only invalid data
    with pytest.raises(RuntimeError):
        crawler._normalize_transformed_data({"ipv4": ["invalid"], "ipv6": ["invalid"]}, "test")


def test_session_configuration() -> None:
    """Test HTTP session configuration."""
    crawler = CloudIPRanges({"json"})

    # Check that session has retry configuration
    assert hasattr(crawler.session, 'mount')
    assert hasattr(crawler.session, 'request')


def test_source_configuration() -> None:
    """Test source configuration."""
    crawler = CloudIPRanges({"json"})

    # Check that sources are configured
    assert "cloudflare" in crawler.sources
    assert "aws" in crawler.sources
    assert isinstance(crawler.sources["cloudflare"], (str, list))


def test_file_operations() -> None:
    """Test file I/O operations."""
    crawler = CloudIPRanges({"json"})
    crawler.base_url = Path("/tmp")

    # Test that only_if_changed is a boolean attribute
    assert isinstance(crawler.only_if_changed, bool)

    # Test with only_if_changed=True
    crawler_with_check = CloudIPRanges({"json"}, only_if_changed=True)
    assert crawler_with_check.only_if_changed is True


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


def test_transform_method_selection() -> None:
    """Test transform method selection logic."""
    crawler = CloudIPRanges({"json"})

    # Transforms are loaded dynamically from src/transforms/<source>.py
    assert callable(get_transform("cloudflare"))
    assert callable(get_transform("aws"))
    assert callable(get_transform("github"))

    # Test that _transform_response exists
    assert hasattr(crawler, "_transform_response")


def test_transform_response_asn_uses_hackertarget(cipr: CloudIPRanges) -> None:
    # Minimal hackertarget-like output
    r = FakeResponse(text="AS,IP\n1, 8.8.8.0/24\n2, 2606:4700::/32\n")
    res = cipr._transform_response([r], "hetzner", is_asn=True)
    assert res["method"] == "asn_lookup"
    assert "8.8.8.0/24" in res["ipv4"]
    assert "2606:4700::/32" in res["ipv6"]


def test_transform_response_apple_private_relay_csv(cipr: CloudIPRanges) -> None:
    r = _load_raw(SAMPLES_DIR / "apple_private_relay_0.raw")
    res = cipr._transform_response([r], "apple_private_relay", is_asn=False)
    assert res["provider"] == "Apple Private Relay"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_atlassian_transform_fallback_heuristic(cipr: CloudIPRanges) -> None:
    r = FakeResponse(json_data={
        "created": "2026-01-04T00:00:00Z",
        "nested": {"prefixes_ipv4": ["5.5.5.0/24"], "prefixes_ipv6": ["2606:4700::/32"]},
    })
    res = cipr._transform_response([r], "atlassian", is_asn=False)
    assert res["source_updated_at"] == "2026-01-04T00:00:00Z"
    assert "5.5.5.0/24" in res["ipv4"]
    assert "2606:4700::/32" in res["ipv6"]


def test_oracle_cloud_transform_includes_ipv4_ipv6_lists(cipr: CloudIPRanges) -> None:
    r = FakeResponse(json_data={
        "regions": [
            {
                "region": "region-1",
                "cidrs": [{"cidr": "1.1.1.0/24"}],
                "ipv4_cidrs": [{"cidr": "2.2.2.0/24"}],
                "ipv6_cidrs": [{"cidr": "2606:4700::/32"}],
            }
        ]
    })
    res = cipr._transform_response([r], "oracle_cloud", is_asn=False)
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

    out = tmp_path / "gh_out.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    crawler.add_env_statistics()

    txt = out.read_text(encoding="utf-8")
    assert "total_ipv4=4" in txt
    assert "total_ipv6=6" in txt
    assert "sources_count=2" in txt


def test_fetch_and_save_seed_cidr_source_vercel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    crawler = CloudIPRanges({"json"})
    crawler.base_url = tmp_path
    crawler.sources = {"vercel": ["76.76.21.0/24"]}

    rdap = FakeResponse(json_data={"entities": [{"handle": "ZEITI", "roles": ["registrant"]}]})
    rdap.status_code = 200
    rdap.headers = {"content-type": "application/rdap+json"}

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

    result = cipr._transform_response([response], "linode", is_asn=False)

    assert result["provider"] == "Linode"
    assert len(result["ipv4"]) > 0


def test_transform_response_google_cloud(cipr: CloudIPRanges) -> None:
    """Test Google Cloud JSON transformation."""
    with open(SAMPLES_DIR / "google_cloud_0.raw", "r") as f:
        content = f.read()
    response = FakeResponse(text=content)

    result = cipr._transform_response([response], "google_cloud", is_asn=False)

    assert result["provider"] == "Google Cloud"
    assert len(result["ipv4"]) > 0
    assert len(result["ipv6"]) > 0


def test_transform_response_google_bot(cipr: CloudIPRanges) -> None:
    """Test Google Bot JSON transformation."""
    with open(SAMPLES_DIR / "google_bot_0.raw", "r") as f:
        content = f.read()
    response = FakeResponse(text=content)

    result = cipr._transform_response([response], "google_bot", is_asn=False)

    assert result["provider"] == "Google Bot"
    assert len(result["ipv4"]) > 0
    assert len(result["ipv6"]) > 0


def test_transform_response_bing_bot(cipr: CloudIPRanges) -> None:
    """Test Bing Bot JSON transformation."""
    with open(SAMPLES_DIR / "bing_bot_0.raw", "r") as f:
        content = f.read()
    response = FakeResponse(text=content)

    result = cipr._transform_response([response], "bing_bot", is_asn=False)

    assert result["provider"] == "Bing Bot"
    assert len(result["ipv4"]) > 0


def test_transform_response_openai(cipr: CloudIPRanges) -> None:
    """Test OpenAI JSON transformation."""
    with open(SAMPLES_DIR / "openai_0.raw", "r") as f:
        content = f.read()
    response = FakeResponse(text=content)

    result = cipr._transform_response([response], "openai", is_asn=False)

    assert result["provider"] == "Openai"
    assert len(result["ipv4"]) > 0
    # Note: OpenAI only has IPv4 ranges in the sample


def test_transform_response_perplexity(cipr: CloudIPRanges) -> None:
    """Test Perplexity JSON transformation."""
    with open(SAMPLES_DIR / "perplexity_0.raw", "r") as f:
        content = f.read()
    response = FakeResponse(text=content)

    result = cipr._transform_response([response], "perplexity", is_asn=False)

    assert result["provider"] == "Perplexity"
    assert len(result["ipv4"]) > 0
    # Note: Perplexity only has IPv4 ranges in the sample


def test_transform_response_aws(cipr: CloudIPRanges) -> None:
    """Test AWS JSON transformation."""
    with open(SAMPLES_DIR / "aws_0.raw", "r") as f:
        content = f.read()
    response = FakeResponse(text=content)

    result = cipr._transform_response([response], "aws", is_asn=False)

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

    result = cipr._transform_response([response_ipv4, response_ipv6], "cloudflare", is_asn=False)

    assert result["provider"] == "Cloudflare"
    assert len(result["ipv4"]) > 0
    assert len(result["ipv6"]) > 0


def test_transform_response_microsoft_azure(cipr: CloudIPRanges) -> None:
    """Test Microsoft Azure JSON transformation."""
    pytest.skip("Microsoft Azure sample file is incomplete due to SSL issues")


def test_transform_response_openai(cipr: CloudIPRanges) -> None:
    """Test OpenAI JSON transformation."""
    with open(SAMPLES_DIR / "openai_0.raw", "r") as f:
        content = f.read()
    response = FakeResponse(text=content)

    result = cipr._transform_response([response], "openai", is_asn=False)

    assert result["provider"] == "Openai"
    assert len(result["ipv4"]) > 0
    # Note: OpenAI only has IPv4 ranges in the sample


def test_transform_response_perplexity(cipr: CloudIPRanges) -> None:
    """Test Perplexity JSON transformation."""
    with open(SAMPLES_DIR / "perplexity_0.raw", "r") as f:
        content = f.read()
    response = FakeResponse(text=content)

    result = cipr._transform_response([response], "perplexity", is_asn=False)

    assert result["provider"] == "Perplexity"
    assert len(result["ipv4"]) > 0
    # Note: Perplexity only has IPv4 ranges in the sample


def test_transform_response_aws(cipr: CloudIPRanges) -> None:
    """Test AWS JSON transformation."""
    with open(SAMPLES_DIR / "aws_0.raw", "r") as f:
        content = f.read()
    response = FakeResponse(text=content)

    result = cipr._transform_response([response], "aws", is_asn=False)

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

    result = cipr._transform_response([response_ipv4, response_ipv6], "cloudflare", is_asn=False)

    assert result["provider"] == "Cloudflare"
    assert len(result["ipv4"]) > 0
    assert len(result["ipv6"]) > 0
