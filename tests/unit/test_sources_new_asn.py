from unittest.mock import Mock
from sources.asn import fetch_and_save_asn_source


class TestNewASNSources:
    def test_upcloud_asn_source(self):
        """Test UpCloud ASN source with multiple ASNs."""
        cipr = Mock()

        def _mock_normalize(data, source_key):
            return {"ipv4": data.get("ipv4", []), "ipv6": data.get("ipv6", []), "method": data.get("method")}

        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}
        cipr._normalize_transformed_data.side_effect = _mock_normalize

        # Mock RIPEstat response
        mock_response = Mock()
        mock_response.json.return_value = {
            "data": {"queried_at": "2025-01-29T00:00:00Z", "prefixes": [{"prefix": "185.1.2.0/24"}, {"prefix": "2a01:1:2::/48"}]}
        }
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}

        cipr.session.get.return_value = mock_response

        result = fetch_and_save_asn_source(cipr, "upcloud", ["AS202053", "AS25697"])

        assert "ipv4" in result
        assert result["method"] == "bgp_announced"
        assert "ipv6" in result
        assert len(result["source_http"]) == 2  # Two ASNs

    def test_gridscale_asn_source(self):
        """Test gridscale ASN source."""
        cipr = Mock()

        def _mock_normalize(data, source_key):
            return {"ipv4": data.get("ipv4", []), "ipv6": data.get("ipv6", []), "method": data.get("method")}

        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}
        cipr._normalize_transformed_data.side_effect = _mock_normalize

        mock_response = Mock()
        mock_response.json.return_value = {"data": {"queried_at": "2025-01-29T00:00:00Z", "prefixes": [{"prefix": "85.236.32.0/19"}]}}
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}

        cipr.session.get.return_value = mock_response

        result = fetch_and_save_asn_source(cipr, "gridscale", ["AS29423"])

        assert "ipv4" in result
        assert result["method"] == "bgp_announced"

    def test_wasabi_asn_source(self):
        """Test Wasabi ASN source."""
        cipr = Mock()

        def _mock_normalize(data, source_key):
            return {"ipv4": data.get("ipv4", []), "ipv6": data.get("ipv6", []), "method": data.get("method")}

        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}
        cipr._normalize_transformed_data.side_effect = _mock_normalize

        mock_response = Mock()
        mock_response.json.return_value = {"data": {"queried_at": "2025-01-29T00:00:00Z", "prefixes": [{"prefix": "45.11.36.0/22"}]}}
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}

        cipr.session.get.return_value = mock_response

        result = fetch_and_save_asn_source(cipr, "wasabi", ["AS395717"])

        assert "ipv4" in result
        assert result["method"] == "bgp_announced"

    def test_ionos_cloud_asn_source(self):
        """Test IONOS Cloud ASN source."""
        cipr = Mock()

        def _mock_normalize(data, source_key):
            return {"ipv4": data.get("ipv4", []), "ipv6": data.get("ipv6", []), "method": data.get("method")}

        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}
        cipr._normalize_transformed_data.side_effect = _mock_normalize

        mock_response = Mock()
        mock_response.json.return_value = {"data": {"queried_at": "2025-01-29T00:00:00Z", "prefixes": [{"prefix": "212.224.0.0/16"}]}}
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}

        cipr.session.get.return_value = mock_response

        result = fetch_and_save_asn_source(cipr, "ionos_cloud", ["AS8560"])

        assert "ipv4" in result
        assert result["method"] == "bgp_announced"

    def test_open_telekom_cloud_asn_source(self):
        """Test Open Telekom Cloud ASN source."""
        cipr = Mock()

        def _mock_normalize(data, source_key):
            return {"ipv4": data.get("ipv4", []), "ipv6": data.get("ipv6", []), "method": data.get("method")}

        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}
        cipr._normalize_transformed_data.side_effect = _mock_normalize

        mock_response = Mock()
        mock_response.json.return_value = {"data": {"queried_at": "2025-01-29T00:00:00Z", "prefixes": [{"prefix": "80.158.0.0/16"}]}}
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}

        cipr.session.get.return_value = mock_response

        result = fetch_and_save_asn_source(cipr, "open_telekom_cloud", ["AS6878"])

        assert "ipv4" in result
        assert result["method"] == "bgp_announced"

    def test_kamatera_asn_source(self):
        """Test Kamatera ASN source."""
        cipr = Mock()

        def _mock_normalize(data, source_key):
            return {"ipv4": data.get("ipv4", []), "ipv6": data.get("ipv6", []), "method": data.get("method")}

        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}
        cipr._normalize_transformed_data.side_effect = _mock_normalize

        mock_response = Mock()
        mock_response.json.return_value = {"data": {"queried_at": "2025-01-29T00:00:00Z", "prefixes": [{"prefix": "185.4.0.0/16"}]}}
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}

        cipr.session.get.return_value = mock_response

        result = fetch_and_save_asn_source(cipr, "kamatera", ["AS36007"])

        assert "ipv4" in result
        assert result["method"] == "bgp_announced"

    def test_ripestat_fallback_to_hackertarget(self):
        """Test fallback to HackerTarget when RIPEstat fails."""
        cipr = Mock()

        def _mock_normalize(data, source_key):
            return {"ipv4": data.get("ipv4", []), "ipv6": data.get("ipv6", []), "method": data.get("method")}

        cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}
        cipr._normalize_transformed_data.side_effect = _mock_normalize

        # Mock RIPEstat failure
        ripestat_response = Mock()
        ripestat_response.raise_for_status.side_effect = Exception("RIPEstat failed")

        # Mock HackerTarget success
        hackertarget_response = Mock()
        hackertarget_response.text = """
        AS,IP
        AS395717,45.11.36.0/22
        """
        hackertarget_response.status_code = 200
        hackertarget_response.headers = {"content-type": "text/plain"}

        cipr.session.get.side_effect = [ripestat_response, hackertarget_response]

        result = fetch_and_save_asn_source(cipr, "wasabi", ["AS395717"])

        assert result["method"] == "asn_lookup"  # Should be fallback method
        assert len(result["source_http"]) == 1  # Only HackerTarget (RIPEstat failed)
