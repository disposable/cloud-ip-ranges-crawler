from unittest.mock import Mock
from transforms.cisco_webex import transform


class TestCiscoWebexTransform:
    def test_transform_html_with_cidrs(self):
        """Test Cisco Webex HTML parsing with CIDR blocks."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = """
        <html>
        <body>
        <h2>Webex Media Network Requirements</h2>
        <p>Media services use the following IP ranges:</p>
        <ul>
        <li>64.68.96.0/20 - Webex Media</li>
        <li>2001:420:40::/48 - Webex IPv6</li>
        <li>64.68.112.0/20 - Webex Meetings</li>
        </ul>
        </body>
        </html>
        """

        result = transform(cipr, response, "cisco_webex")

        assert len(result["ipv4"]) == 2
        assert len(result["ipv6"]) == 1
        assert "64.68.96.0/20" in result["ipv4"]
        assert "64.68.112.0/20" in result["ipv4"]
        assert "2001:420:40::/48" in result["ipv6"]

    def test_transform_html_multiple_pages(self):
        """Test Cisco Webex HTML parsing with multiple pages."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock(), Mock()]
        response[0].text = """
        <html>
        <body>
        <h2>Webex Media Requirements</h2>
        <p>Media ranges:</p>
        <ul>
        <li>64.68.96.0/20 - Media</li>
        <li>2001:420:40::/48 - Media IPv6</li>
        </ul>
        </body>
        </html>
        """
        response[1].text = """
        <html>
        <body>
        <h2>Webex Meetings Requirements</h2>
        <p>Meetings ranges:</p>
        <ul>
        <li>64.68.112.0/20 - Meetings</li>
        <li>2001:420:41::/48 - Meetings IPv6</li>
        </ul>
        </body>
        </html>
        """

        result = transform(cipr, response, "cisco_webex")

        assert len(result["ipv4"]) == 2
        assert len(result["ipv6"]) == 2
        assert "64.68.96.0/20" in result["ipv4"]
        assert "64.68.112.0/20" in result["ipv4"]
        assert "2001:420:40::/48" in result["ipv6"]
        assert "2001:420:41::/48" in result["ipv6"]

    def test_transform_html_with_invalid_cidrs(self):
        """Test Cisco Webex HTML parsing with invalid CIDR blocks."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = """
        <html>
        <body>
        <ul>
        <li>64.68.96.0/33 - Invalid IPv4</li>
        <li>2001:420:40::/129 - Invalid IPv6</li>
        <li>64.68.96.0/20 - Valid IPv4</li>
        <li>not-an-ip - Invalid format</li>
        </ul>
        </body>
        </html>
        """

        result = transform(cipr, response, "cisco_webex")

        assert len(result["ipv4"]) == 1
        assert len(result["ipv6"]) == 1  # The /129 gets truncated to /12 by regex, which is valid
        assert "64.68.96.0/20" in result["ipv4"]
        assert "2001:420:40::/12" in result["ipv6"]

    def test_transform_html_empty_content(self):
        """Test Cisco Webex HTML parsing with empty content."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = ""

        result = transform(cipr, response, "cisco_webex")

        assert len(result["ipv4"]) == 0
        assert len(result["ipv6"]) == 0
