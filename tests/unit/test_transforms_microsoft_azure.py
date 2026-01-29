"""Microsoft Azure transform tests."""

import pytest
from src.cloud_ip_ranges import CloudIPRanges
from tests.unit.conftest import FakeResponse, _has_valid_ipv4, _has_valid_ipv6


def _transform_response(cipr: CloudIPRanges, response: list, source_key: str, is_asn: bool) -> dict:
    """Helper function to replace the removed _transform_response method for tests."""
    if is_asn:
        from src.sources.asn import transform_hackertarget

        transformed_data = transform_hackertarget(cipr, response, source_key)
    else:
        from src.transforms.registry import get_transform

        transform_fn = get_transform(source_key)
        transformed_data = transform_fn(cipr, response, source_key)

    return cipr._normalize_transformed_data(transformed_data, source_key)


class TestMicrosoftAzureTransform:
    def test_microsoft_azure_transform_with_mocked_downloads(self, cipr, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test Microsoft Azure transform with mocked downloads."""
        html_page = FakeResponse(text='<a href="https://download.microsoft.com/ServiceTags_Public.json">download</a>')

        def fake_get(url: str, timeout: int = 10):
            if url.endswith("ServiceTags_Public.json"):
                return FakeResponse(json_data={"values": [{"properties": {"addressPrefixes": ["13.68.0.0/18", "2603:1040::/48"], "systemService": "Azure"}}]})
            return html_page

        monkeypatch.setattr(cipr.session, "get", fake_get)
        res = _transform_response(cipr, [html_page], "microsoft_azure", is_asn=False)

        assert res["provider"] == "Microsoft Azure"
        assert _has_valid_ipv4(res) or _has_valid_ipv6(res)
