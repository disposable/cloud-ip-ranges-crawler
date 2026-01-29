from unittest.mock import Mock
from transforms.scaleway import transform
from tests.unit.conftest import SAMPLES_DIR, _load_raw


class TestScalewayTransform:
    def test_transform_html_with_cidrs(self):
        """Test Scaleway HTML parsing with real sample data."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        # Use real sample data
        sample_content = _load_raw(SAMPLES_DIR / "scaleway_0.raw")
        response = [Mock()]
        response[0].text = sample_content.text

        result = transform(cipr, response, "scaleway")

        # Should extract real CIDRs from Scaleway sample
        assert len(result["ipv4"]) > 0
        assert len(result["ipv6"]) > 0
        # Check for some known Scaleway ranges
        assert any("62.210.0.0/16" in ip for ip in result["ipv4"])
        assert any("2001:bc8::" in ip for ip in result["ipv6"])

    def test_transform_html_with_invalid_cidrs(self):
        """Test Scaleway HTML parsing with real sample data containing invalid CIDRs."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        # Use real sample data - it contains both valid and potentially invalid patterns
        sample_content = _load_raw(SAMPLES_DIR / "scaleway_0.raw")
        response = [Mock()]
        response[0].text = sample_content.text

        result = transform(cipr, response, "scaleway")

        # Should extract only valid CIDRs from real sample
        assert len(result["ipv4"]) > 0
        assert len(result["ipv6"]) > 0
        # Verify no invalid IPv6 addresses (like those with leading zeros)
        for ipv6 in result["ipv6"]:
            # Basic validation - no hextet should start with '0' unless it's just '0'
            hextets = ipv6.split("/")[0].split(":")
            for hextet in hextets:
                assert not (len(hextet) > 1 and hextet.startswith("0") and hextet != "0"), f"Invalid IPv6 hextet found: {hextet} in {ipv6}"

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
