"""Cloudflare transform tests."""

from src.cloud_ip_ranges import CloudIPRanges
from tests.unit.conftest import SAMPLES_DIR, _load_raw


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


class TestCloudflareTransform:
    def test_cloudflare_transform(self, cipr) -> None:
        """Test Cloudflare transform with real sample data."""
        r_v4 = _load_raw(SAMPLES_DIR / "cloudflare_0.raw")
        r_v6 = _load_raw(SAMPLES_DIR / "cloudflare_1.raw")
        res = _transform_response(cipr, [r_v4, r_v6], "cloudflare", is_asn=False)

        assert res["provider"] == "Cloudflare"
        assert len(res["ipv4"]) > 0
        assert len(res["ipv6"]) > 0
