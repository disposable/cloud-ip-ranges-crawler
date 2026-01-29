"""Google Cloud transform tests."""

from src.cloud_ip_ranges import CloudIPRanges
from tests.unit.conftest import SAMPLES_DIR, _load_raw, _has_valid_ipv4, _has_valid_ipv6


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


class TestGoogleCloudTransform:
    def test_google_cloud_transform_has_details(self, cipr) -> None:
        """Test Google Cloud transform with real sample data."""
        r = _load_raw(SAMPLES_DIR / "google_cloud_0.raw")
        res = _transform_response(cipr, [r], "google_cloud", is_asn=False)

        assert res["provider"] == "Google Cloud"
        assert _has_valid_ipv4(res)
        assert _has_valid_ipv6(res)
        assert res.get("details_ipv4") and {"address", "service", "scope"}.issubset(res["details_ipv4"][0].keys())
        assert res["details_ipv6"] and {"address", "service", "scope"}.issubset(res["details_ipv6"][0].keys())
