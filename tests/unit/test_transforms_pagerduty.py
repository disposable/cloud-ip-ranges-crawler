"""PagerDuty transform tests."""

from unittest.mock import Mock
from transforms.pagerduty import transform


class TestPagerdutyTransform:
    def test_pagerduty_transform_with_array_of_ips(self):
        """Test PagerDuty transform with simple array of IP strings."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        # Mock JSON response with simple array (actual API format)
        mock_json = [
            "44.242.69.192",
            "52.89.71.166",
            "54.213.187.133",
        ]

        response = [Mock()]
        response[0].json.return_value = mock_json

        result = transform(cipr, response, "pagerduty")

        # Should extract all IPs as /32
        assert len(result["ipv4"]) == 3
        assert "44.242.69.192/32" in result["ipv4"]
        assert "52.89.71.166/32" in result["ipv4"]
        assert "54.213.187.133/32" in result["ipv4"]

    def test_pagerduty_transform_with_ipv6(self):
        """Test PagerDuty transform handles IPv6 addresses."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        mock_json = [
            "44.242.69.192",
            "2600:1f18:22:dead::face",
        ]

        response = [Mock()]
        response[0].json.return_value = mock_json

        result = transform(cipr, response, "pagerduty")

        assert "44.242.69.192/32" in result["ipv4"]
        assert "2600:1f18:22:dead::face/128" in result["ipv6"]

    def test_pagerduty_transform_with_object_format(self):
        """Test PagerDuty transform with object format containing ipv4/ipv6 fields."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        mock_json = {
            "ipv4": ["35.167.69.145", "44.231.93.240"],
            "ipv6": ["2600:1f18::1"],
        }

        response = [Mock()]
        response[0].json.return_value = mock_json

        result = transform(cipr, response, "pagerduty")

        assert len(result["ipv4"]) == 2
        assert "35.167.69.145/32" in result["ipv4"]
        assert "44.231.93.240/32" in result["ipv4"]
        assert "2600:1f18::1/128" in result["ipv6"]

    def test_pagerduty_transform_deduplicates_ips(self):
        """Test PagerDuty transform deduplicates duplicate IPs."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        mock_json = [
            "44.242.69.192",
            "44.242.69.192",  # Duplicate
        ]

        response = [Mock()]
        response[0].json.return_value = mock_json

        result = transform(cipr, response, "pagerduty")

        assert len(result["ipv4"]) == 1
        assert result["ipv4"][0] == "44.242.69.192/32"

    def test_pagerduty_transform_handles_multiple_regions(self):
        """Test PagerDuty transform handles multiple region responses."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        us_response = Mock()
        us_response.json.return_value = ["44.242.69.192", "52.89.71.166"]

        eu_response = Mock()
        eu_response.json.return_value = ["18.159.153.65", "35.159.34.57"]

        response = [us_response, eu_response]

        result = transform(cipr, response, "pagerduty")

        assert len(result["ipv4"]) == 4
        assert "44.242.69.192/32" in result["ipv4"]
        assert "18.159.153.65/32" in result["ipv4"]

    def test_pagerduty_transform_coverage_notes(self):
        """Test PagerDuty transform includes appropriate coverage notes."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        response = [Mock()]
        response[0].json.return_value = []

        result = transform(cipr, response, "pagerduty")

        # Should note PagerDuty's recommendation
        assert "TLS" in result["coverage_notes"] or "signature" in result["coverage_notes"]

    def test_pagerduty_transform_handles_invalid_content(self):
        """Test PagerDuty transform handles invalid JSON gracefully."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        response = [Mock()]
        response[0].json.side_effect = ValueError("Invalid JSON")

        result = transform(cipr, response, "pagerduty")

        # Should not crash, just return empty lists
        assert isinstance(result["ipv4"], list)
        assert isinstance(result["ipv6"], list)
        assert len(result["ipv4"]) == 0
