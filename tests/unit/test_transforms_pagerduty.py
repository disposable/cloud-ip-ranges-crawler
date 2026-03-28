"""PagerDuty webhook IP transform tests.

These tests verify that PagerDuty IPs are tagged with:
- surface: "webhook" (incoming from PagerDuty)
- region: "US" or "EU"

And that unrecognized formats fail clearly.
"""

from unittest.mock import Mock
from transforms.pagerduty import transform


class TestPagerdutyTransform:
    """Test PagerDuty webhook IP extraction with metadata tagging."""

    def test_pagerduty_transform_with_array_of_ips(self):
        """Test PagerDuty transform with simple array of IP strings."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        # Mock JSON response with simple array (standard API format)
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

    def test_pagerduty_transform_metadata_region_and_surface(self):
        """Test that IPs are tagged with region and surface metadata."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        us_response = Mock()
        us_response.json.return_value = ["44.242.69.192"]

        eu_response = Mock()
        eu_response.json.return_value = ["18.159.153.65"]

        response = [us_response, eu_response]

        result = transform(cipr, response, "pagerduty")

        # Check metadata is preserved
        assert "details_ipv4" in result
        details = result["details_ipv4"]
        assert len(details) == 2

        # Find US entry
        us_entries = [d for d in details if d.get("region") == "US"]
        assert len(us_entries) == 1
        assert us_entries[0]["address"] == "44.242.69.192/32"
        assert us_entries[0]["surface"] == "webhook"

        # Find EU entry
        eu_entries = [d for d in details if d.get("region") == "EU"]
        assert len(eu_entries) == 1
        assert eu_entries[0]["address"] == "18.159.153.65/32"
        assert eu_entries[0]["surface"] == "webhook"

    def test_pagerduty_transform_metadata_with_ipv6(self):
        """Test that IPv6 IPs are also tagged with metadata."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        us_response = Mock()
        us_response.json.return_value = {"ipv6": ["2600:1f18::1"]}

        response = [us_response]

        result = transform(cipr, response, "pagerduty")

        # Check IPv6 metadata
        assert "details_ipv6" in result
        details = result["details_ipv6"]
        assert len(details) == 1
        assert details[0]["address"] == "2600:1f18::1/128"
        assert details[0]["region"] == "US"
        assert details[0]["surface"] == "webhook"

    def test_pagerduty_transform_coverage_notes_explicit(self):
        """Test that coverage notes explicitly state webhook-only scope."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        response = [Mock()]
        response[0].json.return_value = []

        result = transform(cipr, response, "pagerduty")

        # Should be explicit about scope
        assert "webhook" in result["coverage_notes"].lower()
        assert "REST API" in result["coverage_notes"]
        assert "NOT included" in result["coverage_notes"]
        assert "TLS" in result["coverage_notes"] or "signature" in result["coverage_notes"]

    def test_pagerduty_transform_fails_on_dict_without_recognized_keys(self):
        """Test that transform fails on dict payloads without ipv4/ipv6 keys."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        # Dict with unrecognized keys (no ipv4 or ipv6)
        mock_json = {"foo": "bar", "baz": 123}

        response = [Mock()]
        response[0].json.return_value = mock_json

        try:
            transform(cipr, response, "pagerduty")
            assert False, "Should have raised ValueError for dict without recognized keys"
        except ValueError as e:
            assert "missing 'ipv4' or 'ipv6' keys" in str(e)
            assert "foo" in str(e)  # Should mention the actual keys received

    def test_pagerduty_transform_fails_on_invalid_json(self):
        """Test that transform fails clearly on invalid JSON."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        response = [Mock()]
        response[0].json.side_effect = ValueError("Invalid JSON")

        try:
            transform(cipr, response, "pagerduty")
            assert False, "Should have raised ValueError for invalid JSON"
        except ValueError as e:
            assert "Failed to parse" in str(e) or "Invalid JSON" in str(e)

    def test_pagerduty_transform_skips_non_string_items_in_array(self):
        """Test that non-string items in array are skipped."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        # Array with mixed types
        mock_json = [
            "44.242.69.192",
            12345,  # Non-string, should be skipped
            None,   # Non-string, should be skipped
            "52.89.71.166",
        ]

        response = [Mock()]
        response[0].json.return_value = mock_json

        result = transform(cipr, response, "pagerduty")

        # Should only have the two valid string IPs
        assert len(result["ipv4"]) == 2
        assert "44.242.69.192/32" in result["ipv4"]
        assert "52.89.71.166/32" in result["ipv4"]
