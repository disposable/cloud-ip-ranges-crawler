import json
import pytest
from unittest.mock import Mock
from transforms.exoscale import transform
from tests.unit.conftest import SAMPLES_DIR, _load_raw


class TestExoscaleTransform:
    def test_transform_json_with_real_sample(self):
        """Test Exoscale JSON with real sample data."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}

        # Use real sample data
        sample_content = _load_raw(SAMPLES_DIR / "exoscale_0.raw")
        response = [Mock()]
        response[0].json.return_value = json.loads(sample_content.text)

        result = transform(cipr, response, "exoscale")

        # Should extract real CIDRs from Exoscale sample
        assert len(result["ipv4"]) > 0
        # Check for some known Exoscale ranges (based on actual sample structure)
        assert any("89.145." in ip for ip in result["ipv4"])
        assert any("91.92." in ip for ip in result["ipv4"])

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
