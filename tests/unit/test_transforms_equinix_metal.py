from unittest.mock import Mock

from src.transforms.equinix_metal import transform


class TestEquinixMetalTransform:
    def test_transform_geofeed_csv(self):
        """Test Equinix Metal geofeed CSV parsing."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = """147.28.206.0/23,NL,NL-NH,Amsterdam,
2604:1380:f0::/44,NL,NL-NH,Amsterdam,
86.109.13.0/24,NL,NL-NH,Amsterdam,
"""

        result = transform(cipr, response, "equinix_metal")

        assert len(result["ipv4"]) == 2
        assert len(result["ipv6"]) == 1
        assert "147.28.206.0/23" in result["ipv4"]
        assert "86.109.13.0/24" in result["ipv4"]
        assert "2604:1380:f0::/44" in result["ipv6"]

    def test_transform_comments_ignored(self):
        """Test that comment lines are ignored."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = """# This is a comment
1.2.3.0/24,US,US-CA,San Francisco,
# Another comment
5.6.7.0/24,US,US-NY,New York,
"""

        result = transform(cipr, response, "equinix_metal")

        assert len(result["ipv4"]) == 2
        assert "1.2.3.0/24" in result["ipv4"]
        assert "5.6.7.0/24" in result["ipv4"]

    def test_transform_empty_lines_ignored(self):
        """Test that empty lines are ignored."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = "1.2.3.0/24,US,US-CA,San Francisco,\n\n5.6.7.0/24,US,US-NY,New York,"

        result = transform(cipr, response, "equinix_metal")

        assert len(result["ipv4"]) == 2

    def test_transform_provider_name(self):
        """Test that provider name is set correctly."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = "1.2.3.0/24,US,US-CA,San Francisco,"

        result = transform(cipr, response, "equinix_metal")
        assert result["provider"] == "Equinix Metal"
