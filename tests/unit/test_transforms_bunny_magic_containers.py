import json
from unittest.mock import Mock

from src.transforms.bunny_magic_containers import transform


class TestBunnyMagicContainersTransform:
    def test_transform_json_array(self):
        """Test Bunny Magic Containers with JSON array response."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = json.dumps(
            ["104.166.147.46", "109.61.83.105", "109.61.83.248"]
        )

        result = transform(cipr, response, "bunny_magic_containers")

        assert len(result["ipv4"]) == 3
        assert "104.166.147.46/32" in result["ipv4"]
        assert "109.61.83.105/32" in result["ipv4"]

    def test_transform_plain_text(self):
        """Test Bunny Magic Containers with plain text IP list fallback."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = "104.166.147.46\n109.61.83.105\n109.61.83.248"

        result = transform(cipr, response, "bunny_magic_containers")

        assert len(result["ipv4"]) == 3
        assert "104.166.147.46/32" in result["ipv4"]
        assert "109.61.83.105/32" in result["ipv4"]

    def test_transform_empty_lines_ignored(self):
        """Test that empty lines are ignored."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = "1.2.3.4\n\n5.6.7.8"

        result = transform(cipr, response, "bunny_magic_containers")

        assert len(result["ipv4"]) == 2
        assert "1.2.3.4/32" in result["ipv4"]
        assert "5.6.7.8/32" in result["ipv4"]

    def test_transform_provider_name(self):
        """Test that provider name is set correctly."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = '["1.2.3.4"]'

        result = transform(cipr, response, "bunny_magic_containers")
        assert result["provider"] == "Bunny Magic Containers"

    def test_transform_ipv6(self):
        """Test IPv6 addresses get /128 appended."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = json.dumps(["2a01:1:2::3", "2a01:1:2::4"])

        result = transform(cipr, response, "bunny_magic_containers")

        assert len(result["ipv6"]) == 2
        assert "2a01:1:2::3/128" in result["ipv6"]
        assert "2a01:1:2::4/128" in result["ipv6"]
