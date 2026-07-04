from unittest.mock import Mock

from src.transforms.bunny_magic_containers import transform


class TestBunnyMagicContainersTransform:
    def test_transform_plain_text(self):
        """Test Bunny Magic Containers with plain text IP list."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = "104.166.147.46\n109.61.83.105\n109.61.83.248"

        result = transform(cipr, response, "bunny_magic_containers")

        assert len(result["ipv4"]) == 3
        assert "104.166.147.46" in result["ipv4"]
        assert "109.61.83.105" in result["ipv4"]

    def test_transform_empty_lines_ignored(self):
        """Test that empty lines are ignored."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = "1.2.3.4\n\n5.6.7.8"

        result = transform(cipr, response, "bunny_magic_containers")

        assert len(result["ipv4"]) == 2

    def test_transform_provider_name(self):
        """Test that provider name is set correctly."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = "1.2.3.4"

        result = transform(cipr, response, "bunny_magic_containers")
        assert result["provider"] == "Bunny Magic Containers"
