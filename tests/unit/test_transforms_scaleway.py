from unittest.mock import Mock
from transforms.scaleway import transform


class TestScalewayTransform:
    def test_transform_html_with_cidrs(self):
        """Test Scaleway HTML parsing with CIDR blocks."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = """
        <html>
        <body>
        <ul>
        <li>185.1.2.0/24 - Scaleway Paris</li>
        <li>2a01:1:2::/48 - Scaleway Paris IPv6</li>
        <li>51.15.0.0/16 - Scaleway Paris</li>
        </ul>
        </body>
        </html>
        """

        result = transform(cipr, response, "scaleway")

        assert len(result["ipv4"]) == 2
        assert len(result["ipv6"]) == 1
        assert "185.1.2.0/24" in result["ipv4"]
        assert "51.15.0.0/16" in result["ipv4"]
        assert "2a01:1:2::/48" in result["ipv6"]

    def test_transform_html_with_invalid_cidrs(self):
        """Test Scaleway HTML parsing with invalid CIDR blocks."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = """
        <html>
        <body>
        <ul>
        <li>185.1.2.0/33 - Invalid IPv4</li>
        <li>2a01:1:2::/129 - Invalid IPv6</li>
        <li>185.1.2.0/24 - Valid IPv4</li>
        <li>not-an-ip - Invalid format</li>
        </ul>
        </body>
        </html>
        """

        result = transform(cipr, response, "scaleway")

        assert len(result["ipv4"]) == 1
        assert len(result["ipv6"]) == 1
        assert "185.1.2.0/24" in result["ipv4"]
        assert "2a01:1:2::/12" in result["ipv6"]

    def test_transform_html_empty_content(self):
        """Test Scaleway HTML parsing with empty content."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = ""

        result = transform(cipr, response, "scaleway")

        assert len(result["ipv4"]) == 0
        assert len(result["ipv6"]) == 0

    def test_transform_html_mixed_content(self):
        """Test Scaleway HTML parsing with mixed content."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = """
        Some text here
        192.168.1.0/24
        2001:db8::/32
        More text
        10.0.0.0/8
        """

        result = transform(cipr, response, "scaleway")

        assert len(result["ipv4"]) == 2
        assert len(result["ipv6"]) == 1
        assert "192.168.1.0/24" in result["ipv4"]
        assert "10.0.0.0/8" in result["ipv4"]
        assert "2001:db8::/32" in result["ipv6"]
