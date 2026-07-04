from unittest.mock import Mock

from src.transforms.bunny_cdn import transform


class TestBunnyCdnTransform:
    def test_transform_ipv4_and_ipv6_text(self):
        """Test Bunny CDN with plain text IPv4 and IPv6 responses."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [
            Mock(),
            Mock(),
        ]
        response[0].text = "89.187.188.227\r\n89.187.188.228\r\n185.102.217.65"
        response[1].text = "2400:52e0:1500::714:1\r\n2400:52e0:1500::715:1"

        result = transform(cipr, response, "bunny_cdn")

        assert len(result["ipv4"]) == 3
        assert len(result["ipv6"]) == 2
        assert "89.187.188.227" in result["ipv4"]
        assert "185.102.217.65" in result["ipv4"]
        assert "2400:52e0:1500::714:1" in result["ipv6"]

    def test_transform_strips_carriage_return(self):
        """Test that carriage returns are stripped from lines."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = "1.2.3.4\r\n5.6.7.8\r"

        result = transform(cipr, response, "bunny_cdn")

        assert "1.2.3.4" in result["ipv4"]
        assert "5.6.7.8" in result["ipv4"]
        assert not any("\r" in ip for ip in result["ipv4"])

    def test_transform_empty_lines_ignored(self):
        """Test that empty lines are ignored."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = "1.2.3.4\n\n\n5.6.7.8"

        result = transform(cipr, response, "bunny_cdn")

        assert len(result["ipv4"]) == 2

    def test_transform_provider_name(self):
        """Test that provider name is set correctly."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = "1.2.3.4"

        result = transform(cipr, response, "bunny_cdn")
        assert result["provider"] == "Bunny CDN"
