import pytest
from unittest.mock import Mock
from transforms.exoscale import transform


class TestExoscaleTransform:
    def test_transform_json_with_prefixes(self):
        """Test Exoscale JSON with prefixes array."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].json.return_value = {"prefixes": [{"prefix": "185.1.2.0/24"}, {"prefix": "2a01:1:2::/48"}, {"prefix": "185.3.4.0/22"}]}

        result = transform(cipr, response, "exoscale")

        assert len(result["ipv4"]) == 2
        assert len(result["ipv6"]) == 1
        assert "185.1.2.0/24" in result["ipv4"]
        assert "185.3.4.0/22" in result["ipv4"]
        assert "2a01:1:2::/48" in result["ipv6"]

    def test_transform_json_with_direct_arrays(self):
        """Test Exoscale JSON with direct ipv4/ipv6 arrays."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].json.return_value = {"ipv4": ["185.1.2.0/24", "185.3.4.0/22"], "ipv6": ["2a01:1:2::/48"]}

        result = transform(cipr, response, "exoscale")

        assert len(result["ipv4"]) == 2
        assert len(result["ipv6"]) == 1
        assert "185.1.2.0/24" in result["ipv4"]
        assert "185.3.4.0/22" in result["ipv4"]
        assert "2a01:1:2::/48" in result["ipv6"]

    def test_transform_json_empty_prefixes(self):
        """Test Exoscale JSON with empty prefixes."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].json.return_value = {"prefixes": [{"prefix": ""}, {"cidr": "185.1.2.0/24"}]}

        result = transform(cipr, response, "exoscale")

        assert len(result["ipv4"]) == 1
        assert "185.1.2.0/24" in result["ipv4"]

    def test_transform_invalid_json(self):
        """Test Exoscale transform with invalid JSON."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        response = [Mock()]
        response[0].json.side_effect = ValueError("Invalid JSON")

        with pytest.raises(ValueError, match="Failed to parse Exoscale JSON response"):
            transform(cipr, response, "exoscale")
