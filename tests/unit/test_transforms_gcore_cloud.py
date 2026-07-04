from unittest.mock import Mock

from src.transforms.gcore_cloud import transform


class TestGcoreCloudTransform:
    def test_transform_json_ranges(self):
        """Test Gcore Cloud JSON with ranges array."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].json.return_value = {
            "ranges": [
                "5.188.135.94/32",
                "109.61.35.29/32",
                "2a01:1:2::/48",
            ]
        }

        result = transform(cipr, response, "gcore_cloud")

        assert len(result["ipv4"]) == 2
        assert len(result["ipv6"]) == 1
        assert "5.188.135.94/32" in result["ipv4"]
        assert "109.61.35.29/32" in result["ipv4"]
        assert "2a01:1:2::/48" in result["ipv6"]

    def test_transform_empty_ranges(self):
        """Test Gcore Cloud with empty ranges."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].json.return_value = {"ranges": []}

        result = transform(cipr, response, "gcore_cloud")

        assert result["ipv4"] == []
        assert result["ipv6"] == []

    def test_transform_provider_name(self):
        """Test that provider name is set correctly."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].json.return_value = {"ranges": ["1.2.3.0/24"]}

        result = transform(cipr, response, "gcore_cloud")
        assert result["provider"] == "Gcore Cloud"
