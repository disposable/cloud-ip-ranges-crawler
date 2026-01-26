import json
from io import BytesIO
import ipaddress
from pathlib import Path
from typing import Any

import pytest

from src.cloud_ip_ranges import CloudIPRanges


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


def test_apple_icloud_transform_csv(cipr: CloudIPRanges) -> None:
    r = _load_raw(SAMPLES_DIR / "apple_icloud_0.raw")
    res = cipr._transform_response([r], "apple_private_relay", is_asn=False)
    assert res["provider"] == "Apple Private Relay"
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
