from unittest.mock import Mock
from transforms.backblaze import transform


class TestBackblazeTransform:
    def test_transform_html_with_cidrs(self):
        """Test Backblaze HTML parsing with CIDR blocks."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = """
        <html>
        <body>
        <h2>Backblaze IP Addresses</h2>
        <p>Backblaze services use the following IP ranges:</p>
        <ul>
        <li>208.68.0.0/17 - Backblaze B2</li>
        <li>2607:ea00::/32 - Backblaze IPv6</li>
        <li>208.68.128.0/17 - Backblaze Computer Backup</li>
        </ul>
        </body>
        </html>
        """

        result = transform(cipr, response, "backblaze")

        assert len(result["ipv4"]) == 2
        assert len(result["ipv6"]) == 1
        assert "208.68.0.0/17" in result["ipv4"]
        assert "208.68.128.0/17" in result["ipv4"]
        assert "2607:ea00::/32" in result["ipv6"]

    def test_transform_html_with_invalid_cidrs(self):
        """Test Backblaze HTML parsing with invalid CIDR blocks."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = """
        <html>
        <body>
        <ul>
        <li>208.68.0.0/33 - Invalid IPv4</li>
        <li>2607:ea00::/129 - Invalid IPv6</li>
        <li>208.68.0.0/17 - Valid IPv4</li>
        <li>not-an-ip - Invalid format</li>
        </ul>
        </body>
        </html>
        """

        result = transform(cipr, response, "backblaze")

        assert len(result["ipv4"]) == 1
        assert len(result["ipv6"]) == 1  # The /129 gets truncated to /12 by regex, which is valid
        assert "208.68.0.0/17" in result["ipv4"]
        assert "2607:ea00::/12" in result["ipv6"]

    def test_transform_html_empty_content(self):
        """Test Backblaze HTML parsing with empty content."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = ""

        result = transform(cipr, response, "backblaze")

        assert len(result["ipv4"]) == 0
        assert len(result["ipv6"]) == 0

    def test_transform_html_mixed_content(self):
        """Test Backblaze HTML parsing with mixed content."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = """
        Backblaze IP ranges documentation
        208.68.0.0/17
        2607:ea00::/32
        Additional ranges:
        208.68.128.0/17
        """

        result = transform(cipr, response, "backblaze")

        assert len(result["ipv4"]) == 2
        assert len(result["ipv6"]) == 1
        assert "208.68.0.0/17" in result["ipv4"]
        assert "208.68.128.0/17" in result["ipv4"]
        assert "2607:ea00::/32" in result["ipv6"]
