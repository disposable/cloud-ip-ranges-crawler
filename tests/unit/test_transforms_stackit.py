import pytest
from unittest.mock import Mock
from transforms.stackit import transform


class TestStackitTransform:
    def test_transform_json_with_prefixes(self):
        """Test STACKIT JSON with prefixes array."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].json.return_value = {"prefixes": [{"prefix": "185.1.2.0/24"}, {"cidr": "2a01:1:2::/48"}, {"prefix": "185.3.4.0/22"}]}

        result = transform(cipr, response, "stackit")

        assert len(result["ipv4"]) == 2
        assert len(result["ipv6"]) == 1
        assert "185.1.2.0/24" in result["ipv4"]
        assert "185.3.4.0/22" in result["ipv4"]
        assert "2a01:1:2::/48" in result["ipv6"]

    def test_transform_json_with_direct_arrays(self):
        """Test STACKIT JSON with direct ipv4/ipv6 arrays."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].json.return_value = {"ipv4": ["185.1.2.0/24", "185.3.4.0/22"], "ipv6": ["2a01:1:2::/48"]}

        result = transform(cipr, response, "stackit")

        assert len(result["ipv4"]) == 2
        assert len(result["ipv6"]) == 1
        assert "185.1.2.0/24" in result["ipv4"]
        assert "185.3.4.0/22" in result["ipv4"]
        assert "2a01:1:2::/48" in result["ipv6"]

    def test_transform_json_with_result_wrapper(self):
        """Test STACKIT JSON with result wrapper."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].json.return_value = {"result": {"prefixes": [{"prefix": "185.1.2.0/24"}, {"cidr": "2a01:1:2::/48"}]}}

        result = transform(cipr, response, "stackit")

        assert len(result["ipv4"]) == 1
        assert len(result["ipv6"]) == 1
        assert "185.1.2.0/24" in result["ipv4"]
        assert "2a01:1:2::/48" in result["ipv6"]

    def test_transform_json_with_result_direct_arrays(self):
        """Test STACKIT JSON with result wrapper and direct arrays."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].json.return_value = {"result": {"ipv4": ["185.1.2.0/24", "185.3.4.0/22"], "ipv6": ["2a01:1:2::/48"]}}

        result = transform(cipr, response, "stackit")

        assert len(result["ipv4"]) == 2
        assert len(result["ipv6"]) == 1
        assert "185.1.2.0/24" in result["ipv4"]
        assert "185.3.4.0/22" in result["ipv4"]
        assert "2a01:1:2::/48" in result["ipv6"]

    def test_transform_fallback_to_text_parsing(self):
        """Test STACKIT transform falling back to text parsing."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].json.side_effect = ValueError("Invalid JSON")
        response[0].text = """
        185.1.2.0/24
        2a01:1:2::/48
        185.3.4.0/22
        """

        result = transform(cipr, response, "stackit")

        assert len(result["ipv4"]) == 2
        assert len(result["ipv6"]) == 1
        assert "185.1.2.0/24" in result["ipv4"]
        assert "185.3.4.0/22" in result["ipv4"]
        assert "2a01:1:2::/48" in result["ipv6"]

    def test_transform_empty_prefixes(self):
        """Test STACKIT JSON with empty prefixes."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].json.return_value = {"prefixes": [{"prefix": ""}, {"cidr": "185.1.2.0/24"}]}

        result = transform(cipr, response, "stackit")

        assert len(result["ipv4"]) == 1
        assert "185.1.2.0/24" in result["ipv4"]

    def test_transform_completely_invalid_response(self):
        """Test STACKIT transform with completely invalid response."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].json.side_effect = ValueError("Invalid JSON")
        response[0].text = "not valid ip content"

        with pytest.raises(ValueError, match="Failed to parse STACKIT response as JSON or text"):
            transform(cipr, response, "stackit")
