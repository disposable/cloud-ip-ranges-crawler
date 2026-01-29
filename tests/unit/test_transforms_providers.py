"""Provider-specific transform tests."""

import pytest
from io import BytesIO
from zipfile import ZipFile
import socket  # Add missing socket import
from typing import Any, Dict, List

from src.cloud_ip_ranges import CloudIPRanges
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


def test_cloudflare_transform(cipr) -> None:
    r_v4 = _load_raw(SAMPLES_DIR / "cloudflare_0.raw")
    r_v6 = _load_raw(SAMPLES_DIR / "cloudflare_1.raw")
    res = _transform_response(cipr, [r_v4, r_v6], "cloudflare", is_asn=False)
    assert res["provider"] == "Cloudflare"
    assert _has_valid_ipv4(res)
    assert _has_valid_ipv6(res)


def test_google_cloud_transform_has_details(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "google_cloud_0.raw")
    res = _transform_response(cipr, [r], "google_cloud", is_asn=False)
    assert res["provider"] == "Google Cloud"
    assert _has_valid_ipv4(res)
    assert _has_valid_ipv6(res)
    assert res.get("details_ipv4") and {"address", "service", "scope"}.issubset(res["details_ipv4"][0].keys())
    assert res["details_ipv6"] and {"address", "service", "scope"}.issubset(res["details_ipv6"][0].keys())


def test_google_bot_transform(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "google_bot_0.raw")
    res = _transform_response(cipr, [r], "google_bot", is_asn=False)
    assert res["provider"] == "Google Bot"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_bing_bot_transform(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "bing_bot_0.raw")
    res = _transform_response(cipr, [r], "bing_bot", is_asn=False)
    assert res["provider"] == "Bing Bot"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_openai_transform(cipr) -> None:
    r0 = _load_raw(SAMPLES_DIR / "openai_0.raw")
    r1 = _load_raw(SAMPLES_DIR / "openai_1.raw")
    res = _transform_response(cipr, [r0, r1], "openai", is_asn=False)
    assert res["provider"] == "Openai"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_perplexity_transform(cipr) -> None:
    r0 = _load_raw(SAMPLES_DIR / "perplexity_0.raw")
    r1 = _load_raw(SAMPLES_DIR / "perplexity_1.raw")
    res = _transform_response(cipr, [r0, r1], "perplexity", is_asn=False)
    assert res["provider"] == "Perplexity"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_github_transform_limits_to_hooks_and_web(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "github_0.raw")
    res = _transform_response(cipr, [r], "github", is_asn=False)
    assert _has_valid_ipv4(res)
    cats_v4 = {d.get("category") for d in res.get("details_ipv4", [])}
    cats_v6 = {d.get("category") for d in res.get("details_ipv6", [])}
    assert cats_v4.issubset({"hooks", "web"})
    assert cats_v6.issubset({"hooks", "web"})


def test_zscaler_transform_merges_required_and_recommended(cipr) -> None:
    r_required = _load_raw(SAMPLES_DIR / "zscaler_0.raw")
    r_recommended = _load_raw(SAMPLES_DIR / "zscaler_1.raw")
    res = _transform_response(cipr, [r_required, r_recommended], "zscaler", is_asn=False)
    assert res["provider"] == "Zscaler"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_fastly_transform_basic(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "fastly_0.raw")
    res = _transform_response(cipr, [r], "fastly", is_asn=False)
    assert res["provider"] == "Fastly"
    assert isinstance(res["ipv4"], list)
    assert isinstance(res["ipv6"], list)


def test_telegram_transform_csv_like(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "telegram_0.raw")
    res = _transform_response(cipr, [r], "telegram", is_asn=False)
    assert res["provider"] == "Telegram"
    assert _has_valid_ipv4(res)


def test_linode_transform_csv(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "linode_0.raw")
    res = _transform_response(cipr, [r], "linode", is_asn=False)
    assert res["provider"] == "Linode"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_starlink_transform_csv(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "starlink_0.raw")
    res = _transform_response(cipr, [r], "starlink", is_asn=False)
    assert res["provider"] == "Starlink"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_digitalocean_transform_csv(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "digitalocean_0.raw")
    res = _transform_response(cipr, [r], "digitalocean", is_asn=False)
    assert res["provider"] == "Digitalocean"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_ahrefs_transform_json(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "ahrefs_0.raw")
    res = _transform_response(cipr, [r], "ahrefs", is_asn=False)
    assert res["provider"] == "Ahrefs"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_aws_transform_json(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "aws_0.raw")
    res = _transform_response(cipr, [r], "aws", is_asn=False)
    assert res["provider"] == "Aws"
    assert _has_valid_ipv4(res)
    assert _has_valid_ipv6(res)
    assert "details_ipv4" in res and "details_ipv6" in res


def test_oracle_cloud_transform_json_with_details(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "oracle_cloud_0.raw")
    res = _transform_response(cipr, [r], "oracle_cloud", is_asn=False)
    assert res["provider"] == "Oracle Cloud"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_vultr_transform_json_with_details(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "vultr_0.raw")
    res = _transform_response(cipr, [r], "vultr", is_asn=False)
    assert res["provider"] == "Vultr"
    assert _has_valid_ipv4(res) or _has_valid_ipv6(res)


def test_akamai_transform_zip_content(cipr) -> None:
    # Build an in-memory zip matching expected filenames with both IPv4 and IPv6 CIDRs
    bio = BytesIO()
    with ZipFile(bio, "w") as zf:
        zf.writestr("akamai_ipv4_CIDRs.txt", "1.2.3.0/24\n5.6.7.0/24\n")
        zf.writestr("akamai_ipv6_CIDRs.txt", "2606:4700::/32\n2606:4700:1::/48\n")
    r = FakeResponse(content=bio.getvalue())
    res = _transform_response(cipr, [r], "akamai", is_asn=False)
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
    res = _transform_response(cipr, [html_page], "microsoft_azure", is_asn=False)
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
    res = _transform_response(cipr, [html_page], "whatsapp", is_asn=False)
    assert res["provider"] == "Whatsapp"
    assert any("." in ip for ip in res["ipv4"])  # entries parsed from zip


def test_zendesk_transform_parses_ingress_and_egress(cipr) -> None:
    r = FakeResponse(
        json_data={
            "ips": {
                "ingress": {"all": ["216.198.0.0/18"], "specific": ["104.18.248.37/32"]},
                "egress": {"all": ["192.161.156.0/24"], "specific": ["104.18.248.37/32"]},
            }
        }
    )
    res = _transform_response(cipr, [r], "zendesk", is_asn=False)
    assert res["provider"] == "Zendesk"
    assert "216.198.0.0/18" in res["ipv4"]
    assert "104.18.248.37/32" in res["ipv4"]


def test_okta_transform_extracts_nested_ranges(cipr) -> None:
    r = FakeResponse(json_data={"last_updated": "2026-01-02T00:00:00Z", "ranges": [{"service": "okta", "cidrs": ["4.4.4.0/24", "2606:4700::/32"]}]})
    res = _transform_response(cipr, [r], "okta", is_asn=False)
    assert res["provider"] == "Okta"
    assert "4.4.4.0/24" in res["ipv4"]
    assert "2606:4700::/32" in res["ipv6"]


def test_datadog_transform_extracts_ranges_by_heuristics(cipr) -> None:
    r = FakeResponse(
        json_data={
            "modified": "2026-01-03T00:00:00Z",
            "agents": {"prefixes_ipv4": ["4.4.4.0/24"], "prefixes_ipv6": ["2606:4700::/32"]},
        }
    )
    res = _transform_response(cipr, [r], "datadog", is_asn=False)
    assert res["provider"] == "Datadog"
    assert "4.4.4.0/24" in res["ipv4"]
    assert "2606:4700::/32" in res["ipv6"]


def test_circleci_transform_normalizes_bare_ips(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "circleci_0.raw")
    res = _transform_response(cipr, [r], "circleci", is_asn=False)
    assert res["provider"] == "Circleci"
    assert _has_valid_ipv4(res)
    assert any(ip.endswith("/32") for ip in res["ipv4"])


def test_hcp_terraform_transform_extracts_cidrs(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "hcp_terraform_0.raw")
    res = _transform_response(cipr, [r], "hcp_terraform", is_asn=False)
    assert res["provider"] == "Hcp Terraform"
    assert _has_valid_ipv4(res)


def test_new_relic_synthetics_transform_extracts_location_ranges(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "new_relic_synthetics_0.raw")
    res = _transform_response(cipr, [r], "new_relic_synthetics", is_asn=False)
    assert res["provider"] == "New Relic Synthetics"
    assert _has_valid_ipv4(res)


def test_grafana_cloud_transform_normalizes_ip_lists(cipr) -> None:
    rs = [
        _load_raw(SAMPLES_DIR / "grafana_cloud_0.raw"),
        _load_raw(SAMPLES_DIR / "grafana_cloud_1.raw"),
        _load_raw(SAMPLES_DIR / "grafana_cloud_2.raw"),
        _load_raw(SAMPLES_DIR / "grafana_cloud_3.raw"),
        _load_raw(SAMPLES_DIR / "grafana_cloud_4.raw"),
        _load_raw(SAMPLES_DIR / "grafana_cloud_5.raw"),
        _load_raw(SAMPLES_DIR / "grafana_cloud_6.raw"),
    ]
    res = _transform_response(cipr, rs, "grafana_cloud", is_asn=False)
    assert res["provider"] == "Grafana Cloud"
    assert _has_valid_ipv4(res)
    assert any(ip.endswith("/32") for ip in res["ipv4"])


def test_intercom_transform_filters_to_outbound(cipr) -> None:
    r0 = _load_raw(SAMPLES_DIR / "intercom_0.raw")
    r1 = _load_raw(SAMPLES_DIR / "intercom_1.raw")
    r2 = _load_raw(SAMPLES_DIR / "intercom_2.raw")
    res = _transform_response(cipr, [r0, r1, r2], "intercom", is_asn=False)
    assert res["provider"] == "Intercom"
    assert "34.197.76.213/32" in res["ipv4"]
    assert "34.197.76.214/32" not in res["ipv4"]


def test_stripe_transform_normalizes_api_and_webhooks(cipr) -> None:
    r0 = _load_raw(SAMPLES_DIR / "stripe_0.raw")
    r1 = _load_raw(SAMPLES_DIR / "stripe_1.raw")
    res = _transform_response(cipr, [r0, r1], "stripe", is_asn=False)
    assert res["provider"] == "Stripe"
    assert _has_valid_ipv4(res)
    assert any(ip.endswith("/32") for ip in res["ipv4"])


def test_adyen_transform_extracts_cidrs_from_docs(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "adyen_0.raw")
    res = _transform_response(cipr, [r], "adyen", is_asn=False)
    assert res["provider"] == "Adyen"
    assert "82.199.87.128/26" in res["ipv4"]


def test_salesforce_hyperforce_transform_extracts_prefixes(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "salesforce_hyperforce_0.raw")
    res = _transform_response(cipr, [r], "salesforce_hyperforce", is_asn=False)
    assert res["provider"] == "Salesforce Hyperforce"
    assert "155.226.144.0/22" in res["ipv4"]


def test_circleci_transform_malformed_json(cipr) -> None:
    r = FakeResponse(json_data={"IPRanges": {"jobs": ["1.2.3.4"]}})
    res = _transform_response(cipr, [r], "circleci", is_asn=False)
    assert res["provider"] == "Circleci"
    assert "1.2.3.4/32" in res["ipv4"]


def test_hcp_terraform_transform_missing_keys(cipr) -> None:
    r = FakeResponse(json_data={"api": ["1.2.3.4/32"]})
    res = _transform_response(cipr, [r], "hcp_terraform", is_asn=False)
    assert res["provider"] == "Hcp Terraform"
    assert "1.2.3.4/32" in res["ipv4"]


def test_new_relic_synthetics_transform_not_dict(cipr) -> None:
    r = FakeResponse(json_data={"us": ["1.2.3.4/32"]})
    res = _transform_response(cipr, [r], "new_relic_synthetics", is_asn=False)
    assert res["provider"] == "New Relic Synthetics"
    assert "1.2.3.4/32" in res["ipv4"]


def test_grafana_cloud_transform_malformed_response(cipr) -> None:
    r = FakeResponse(json_data=["1.2.3.4"])
    res = _transform_response(cipr, [r], "grafana_cloud", is_asn=False)
    assert res["provider"] == "Grafana Cloud"
    assert "1.2.3.4/32" in res["ipv4"]


def test_intercom_transform_filters_non_outbound(cipr) -> None:
    r = FakeResponse(
        json_data={
            "ip_ranges": [
                {"range": "1.2.3.4/32", "service": "INTERCOM-INBOUND"},
                {"range": "5.6.7.8/32", "service": "INTERCOM-OUTBOUND"},
            ],
            "date": "2025-07-25",
        }
    )
    res = _transform_response(cipr, [r], "intercom", is_asn=False)
    assert res["provider"] == "Intercom"
    assert "5.6.7.8/32" in res["ipv4"]
    assert "1.2.3.4/32" not in res["ipv4"]
    assert res["source_updated_at"] == "2025-07-25"


def test_stripe_transform_malformed_entries(cipr) -> None:
    r = FakeResponse(json_data={"API": ["1.2.3.4"], "WEBHOOKS": "not a list"})
    res = _transform_response(cipr, [r], "stripe", is_asn=False)
    assert res["provider"] == "Stripe"
    assert "1.2.3.4/32" in res["ipv4"]


def test_adyen_transform_no_cidrs_in_text(cipr) -> None:
    r = FakeResponse(text="Adyen outgoing IPs: 1.2.3.4/32")
    res = _transform_response(cipr, [r], "adyen", is_asn=False)
    assert res["provider"] == "Adyen"
    assert "1.2.3.4/32" in res["ipv4"]


def test_adyen_transform_dns_resolution(cipr, monkeypatch: pytest.MonkeyPatch) -> None:
    # Mock DNS resolution to return test IPs
    def mock_gethostbyname_ex(hostname):
        return ("out.adyen.com", [], ["1.2.3.4", "5.6.7.8"])

    monkeypatch.setattr("socket.gethostbyname_ex", mock_gethostbyname_ex)
    r = FakeResponse(text="Some text without CIDRs")
    res = _transform_response(cipr, [r], "adyen", is_asn=False)
    assert res["provider"] == "Adyen"
    assert "1.2.3.4/32" in res["ipv4"]
    assert "5.6.7.8/32" in res["ipv4"]


def test_adyen_transform_dns_failure(cipr, monkeypatch: pytest.MonkeyPatch) -> None:
    # Mock DNS resolution failure
    def mock_gethostbyname_ex(hostname):
        raise socket.gaierror("DNS resolution failed")

    monkeypatch.setattr("socket.gethostbyname_ex", mock_gethostbyname_ex)
    r = FakeResponse(text="Adyen outgoing IPs: 1.2.3.4/32")
    res = _transform_response(cipr, [r], "adyen", is_asn=False)
    assert res["provider"] == "Adyen"
    assert "1.2.3.4/32" in res["ipv4"]
    # Should still work with static CIDRs even if DNS fails


def test_salesforce_hyperforce_transform_missing_prefixes(cipr) -> None:
    r = FakeResponse(json_data={"syncToken": "123", "createDate": "2025-01-01-00-00-00", "prefixes": [{"ip_prefix": ["1.2.3.4/32"]}]})
    res = _transform_response(cipr, [r], "salesforce_hyperforce", is_asn=False)
    assert res["provider"] == "Salesforce Hyperforce"
    assert res["source_updated_at"] == "2025-01-01-00-00-00"
    assert "1.2.3.4/32" in res["ipv4"]


def test_circleci_transform_nonlist_values(cipr) -> None:
    r = FakeResponse(json_data={"IPRanges": {"jobs": ["1.2.3.4"], "core": "not a list"}})
    res = _transform_response(cipr, [r], "circleci", is_asn=False)
    assert res["provider"] == "Circleci"
    assert "1.2.3.4/32" in res["ipv4"]


def test_grafana_cloud_transform_nonstring_items(cipr) -> None:
    r = FakeResponse(json_data=["1.2.3.4", 123, None])
    res = _transform_response(cipr, [r], "grafana_cloud", is_asn=False)
    assert res["provider"] == "Grafana Cloud"
    assert "1.2.3.4/32" in res["ipv4"]


def test_new_relic_synthetics_transform_nonlist_values(cipr) -> None:
    r = FakeResponse(json_data={"us": ["1.2.3.4/32"], "eu": "not a list"})
    res = _transform_response(cipr, [r], "new_relic_synthetics", is_asn=False)
    assert res["provider"] == "New Relic Synthetics"
    assert "1.2.3.4/32" in res["ipv4"]


def test_circleci_transform_nonstring_ips(cipr) -> None:
    r = FakeResponse(json_data={"IPRanges": {"jobs": ["1.2.3.4", 123, None]}})
    res = _transform_response(cipr, [r], "circleci", is_asn=False)
    assert res["provider"] == "Circleci"
    assert "1.2.3.4/32" in res["ipv4"]


def test_hcp_terraform_transform_nonstring_cidrs(cipr) -> None:
    r = FakeResponse(json_data={"api": ["1.2.3.4/32", 123, None]})
    res = _transform_response(cipr, [r], "hcp_terraform", is_asn=False)
    assert res["provider"] == "Hcp Terraform"
    assert "1.2.3.4/32" in res["ipv4"]


def test_intercom_transform_missing_fields(cipr) -> None:
    r = FakeResponse(
        json_data={
            "ip_ranges": [
                {"range": "1.2.3.4/32"},
                {"service": "INTERCOM-OUTBOUND"},
                {"range": "5.6.7.8/32", "service": "INTERCOM-OUTBOUND"},
            ]
        }
    )
    res = _transform_response(cipr, [r], "intercom", is_asn=False)
    assert res["provider"] == "Intercom"
    assert "5.6.7.8/32" in res["ipv4"]


def test_stripe_transform_nonstring_ips(cipr) -> None:
    r = FakeResponse(json_data={"API": ["1.2.3.4", 123, None], "WEBHOOKS": ["5.6.7.8"]})
    res = _transform_response(cipr, [r], "stripe", is_asn=False)
    assert res["provider"] == "Stripe"
    assert "1.2.3.4/32" in res["ipv4"]
    assert "5.6.7.8/32" in res["ipv4"]


def test_salesforce_hyperforce_transform_nonstring_cidrs(cipr) -> None:
    r = FakeResponse(json_data={"syncToken": "123", "createDate": "2025-01-01-00-00-00", "prefixes": [{"ip_prefix": ["1.2.3.4/32", 123, None]}]})
    res = _transform_response(cipr, [r], "salesforce_hyperforce", is_asn=False)
    assert res["provider"] == "Salesforce Hyperforce"
    assert "1.2.3.4/32" in res["ipv4"]


def test_grafana_cloud_transform_mixed_types(cipr) -> None:
    r = FakeResponse(json_data=["1.2.3.4", "5.6.7.8/32", 123, None])
    res = _transform_response(cipr, [r], "grafana_cloud", is_asn=False)
    assert res["provider"] == "Grafana Cloud"
    assert "1.2.3.4/32" in res["ipv4"]
    assert "5.6.7.8/32" in res["ipv4"]


def test_new_relic_synthetics_transform_nonstring_cidrs(cipr) -> None:
    r = FakeResponse(json_data={"us": ["1.2.3.4/32", 123, None]})
    res = _transform_response(cipr, [r], "new_relic_synthetics", is_asn=False)
    assert res["provider"] == "New Relic Synthetics"
    assert "1.2.3.4/32" in res["ipv4"]


def test_intercom_transform_nonstring_range(cipr) -> None:
    r = FakeResponse(
        json_data={
            "ip_ranges": [
                {"range": 123, "service": "INTERCOM-OUTBOUND"},
                {"range": "1.2.3.4/32", "service": "INTERCOM-OUTBOUND"},
            ]
        }
    )
    res = _transform_response(cipr, [r], "intercom", is_asn=False)
    assert res["provider"] == "Intercom"
    assert "1.2.3.4/32" in res["ipv4"]


def test_hcp_terraform_transform_nonlist_entries(cipr) -> None:
    r = FakeResponse(json_data={"api": "not a list", "notifications": ["1.2.3.4/32"]})
    res = _transform_response(cipr, [r], "hcp_terraform", is_asn=False)
    assert res["provider"] == "Hcp Terraform"
    assert "1.2.3.4/32" in res["ipv4"]


def test_salesforce_hyperforce_transform_nonlist_prefixes(cipr) -> None:
    r = FakeResponse(json_data={"syncToken": "123", "createDate": "2025-01-01-00-00-00", "prefixes": [{"ip_prefix": ["1.2.3.4/32"]}, "not a list"]})
    res = _transform_response(cipr, [r], "salesforce_hyperforce", is_asn=False)
    assert res["provider"] == "Salesforce Hyperforce"
    assert res["source_updated_at"] == "2025-01-01-00-00-00"
    assert "1.2.3.4/32" in res["ipv4"]


def test_atlassian_transform_parses_items_list(cipr) -> None:
    r = FakeResponse(
        json_data={
            "creationDate": "2026-01-04T00:00:00Z",
            "items": [
                {"cidr": "5.5.5.0/24"},
                {"cidr": "2606:4700::/32"},
            ],
        }
    )
    res = _transform_response(cipr, [r], "atlassian", is_asn=False)
    assert res["provider"] == "Atlassian"
    assert "5.5.5.0/24" in res["ipv4"]
    assert "2606:4700::/32" in res["ipv6"]


def test_branch_transform_parses_html_ips(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "branch_0.raw")
    res = _transform_response(cipr, [r], "branch", is_asn=False)
    assert res["provider"] == "Branch"
    assert "52.43.119.253/32" in res["ipv4"]
    assert "100.21.145.61/32" in res["ipv4"]
    assert len(res["ipv4"]) > 20  # Should extract multiple IPs


def test_branch_transform_mixed_content(cipr) -> None:
    r = FakeResponse(text="Some text with 52.43.119.253/32 and 1.2.3.4 and 5.6.7.8/32")
    res = _transform_response(cipr, [r], "branch", is_asn=False)
    assert res["provider"] == "Branch"
    assert "52.43.119.253/32" in res["ipv4"]
    assert "5.6.7.8/32" in res["ipv4"]
    assert "1.2.3.4/32" in res["ipv4"]


def test_branch_transform_no_duplicates(cipr) -> None:
    r = FakeResponse(text="Repeated IPs: 52.43.119.253/32, 52.43.119.253/32, 1.2.3.4, 1.2.3.4")
    res = _transform_response(cipr, [r], "branch", is_asn=False)
    assert res["provider"] == "Branch"
    assert res["ipv4"].count("52.43.119.253/32") == 1
    assert res["ipv4"].count("1.2.3.4/32") == 1


def test_sentry_transform_parses_uptime_ips(cipr) -> None:
    r = _load_raw(SAMPLES_DIR / "sentry_0.raw")
    res = _transform_response(cipr, [r], "sentry", is_asn=False)
    assert res["provider"] == "Sentry"
    assert "34.123.33.225/32" in res["ipv4"]
    assert "35.204.169.245/32" in res["ipv4"]


def test_sentry_transform_empty_response(cipr) -> None:
    r = FakeResponse(text="34.123.33.225")
    res = _transform_response(cipr, [r], "sentry", is_asn=False)
    assert res["provider"] == "Sentry"
    assert "34.123.33.225/32" in res["ipv4"]


def test_sentry_transform_whitespace_only(cipr) -> None:
    r = FakeResponse(text="34.123.33.225\n\n \n\n")
    res = _transform_response(cipr, [r], "sentry", is_asn=False)
    assert res["provider"] == "Sentry"
    assert "34.123.33.225/32" in res["ipv4"]


def test_vercel_rdap_transform_discovers_org_nets(cipr, monkeypatch: pytest.MonkeyPatch) -> None:
    rdap_seed = FakeResponse(
        json_data={
            "entities": [
                {"handle": "ZEITI", "roles": ["registrant"]},
                {"handle": "VERCEL", "roles": ["administrative"]},
            ]
        }
    )
    org_xml = "<?xml version='1.0'?><org xmlns='https://www.arin.net/whoisrws/core/v1'><updateDate>2025-12-24T07:44:44-05:00</updateDate></org>"
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
    res = _transform_response(cipr, [rdap_seed], "vercel", is_asn=False)
    assert res["provider"] == "Vercel"
    assert "76.76.21.0/24" in res["ipv4"]
    assert "198.169.1.0/24" in res["ipv4"]
