from unittest.mock import Mock
from transforms.backblaze import transform
from tests.unit.conftest import SAMPLES_DIR, _load_raw


class TestBackblazeTransform:
    def test_transform_html_with_cidrs(self):
        """Test Backblaze HTML parsing with real sample data."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        # Use real sample data
        sample_content = _load_raw(SAMPLES_DIR / "backblaze_0.raw")
        response = [Mock()]
        response[0].text = sample_content.text

        result = transform(cipr, response, "backblaze")

        # Should extract real CIDRs from Backblaze sample
        assert len(result["ipv4"]) > 0
        assert len(result["ipv6"]) > 0
        # Check for some known Backblaze ranges
        assert any("45.11.36.0/22" in ip for ip in result["ipv4"])
        assert any("2605:72c0::/32" in ip for ip in result["ipv6"])

    def test_transform_html_with_invalid_cidrs(self):
        """Test Backblaze HTML parsing with real sample data containing invalid patterns."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        # Use real sample data - it contains both valid and potentially invalid patterns
        sample_content = _load_raw(SAMPLES_DIR / "backblaze_0.raw")
        response = [Mock()]
        response[0].text = sample_content.text

        result = transform(cipr, response, "backblaze")

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
