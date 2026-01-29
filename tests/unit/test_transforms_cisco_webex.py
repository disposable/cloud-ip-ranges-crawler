from unittest.mock import Mock
from transforms.cisco_webex import transform
from tests.unit.conftest import SAMPLES_DIR, _load_raw


class TestCiscoWebexTransform:
    def test_transform_html_with_cidrs(self):
        """Test Cisco Webex HTML parsing with real sample data."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        # Use real sample data from both pages
        sample_content1 = _load_raw(SAMPLES_DIR / "cisco_webex_0.raw")
        sample_content2 = _load_raw(SAMPLES_DIR / "cisco_webex_1.raw")

        response = [Mock(), Mock()]
        response[0].text = sample_content1.text
        response[1].text = sample_content2.text

        result = transform(cipr, response, "cisco_webex")

        # Should extract real CIDRs from Cisco Webex samples
        assert len(result["ipv4"]) > 0
        assert len(result["ipv6"]) > 0
        # Check for some known Cisco Webex ranges
        assert any("4.152.214.0/24" in ip for ip in result["ipv4"])
        assert any("2402:2500::/34" in ip for ip in result["ipv6"])

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
        """Test Cisco Webex HTML parsing with real sample data containing invalid patterns."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        # Use real sample data - it contains both valid and potentially invalid patterns
        sample_content1 = _load_raw(SAMPLES_DIR / "cisco_webex_0.raw")
        sample_content2 = _load_raw(SAMPLES_DIR / "cisco_webex_1.raw")

        response = [Mock(), Mock()]
        response[0].text = sample_content1.text
        response[1].text = sample_content2.text

        result = transform(cipr, response, "cisco_webex")

        # Should extract only valid CIDRs from real samples
        assert len(result["ipv4"]) > 0
        assert len(result["ipv6"]) > 0
        # Verify no invalid IPv6 addresses (like those with leading zeros)
        for ipv6 in result["ipv6"]:
            # Basic validation - no hextet should start with '0' unless it's just '0'
            hextets = ipv6.split("/")[0].split(":")
            for hextet in hextets:
                assert not (len(hextet) > 1 and hextet.startswith("0") and hextet != "0"), f"Invalid IPv6 hextet found: {hextet} in {ipv6}"

    def test_transform_html_empty_content(self):
        """Test Cisco Webex HTML parsing with empty content."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].text = ""

        result = transform(cipr, response, "cisco_webex")

        assert len(result["ipv4"]) == 0
        assert len(result["ipv6"]) == 0
