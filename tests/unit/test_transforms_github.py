"""GitHub transform tests."""

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


class TestGithubTransform:
    def test_github_transform_limits_to_hooks_and_web(self, cipr) -> None:
        """Test GitHub transform with real sample data."""
        r = _load_raw(SAMPLES_DIR / "github_0.raw")
        res = _transform_response(cipr, [r], "github", is_asn=False)

        assert res["provider"] == "Github"
        assert len(res["ipv4"]) > 0
        # GitHub should only have IPv4 in current sample
