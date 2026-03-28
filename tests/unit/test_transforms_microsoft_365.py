"""Microsoft 365 transform tests."""

from unittest.mock import Mock
from transforms.microsoft_365 import transform


class TestMicrosoft365Transform:
    def test_microsoft_365_transform_extracts_guid_from_docs(self):
        """Test Microsoft 365 transform extracts ClientRequestId from documentation."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "details_ipv4": [], "details_ipv6": [], "source": ""}

        # Mock documentation HTML with GUID
        doc_html = """
        <html>
        <body>
        <p>Example URL: https://endpoints.office.com/endpoints/Worldwide?ClientRequestId=b10c5ed1-bad1-445f-b386-b919946339a7</p>
        </body>
        </html>
        """

        # Mock API response
        mock_api_json = [{"id": 1, "serviceArea": "Exchange", "ips": ["23.103.132.0/22", "2a01:111:f403::/48"], "category": "Allow"}]

        doc_response = Mock()
        doc_response.text = doc_html

        api_response = Mock()
        api_response.json.return_value = mock_api_json
        api_response.raise_for_status.return_value = None

        cipr.session.get.return_value = api_response

        result = transform(cipr, [doc_response], "microsoft_365")

        # Should have extracted IPs
        assert len(result["ipv4"]) == 1
        assert "23.103.132.0/22" in result["ipv4"]
        assert "2a01:111:f403::/48" in result["ipv6"]

        # Should have used the extracted GUID
        cipr.session.get.assert_called_once()
        call_args = cipr.session.get.call_args[0][0]
        assert "ClientRequestId=b10c5ed1-bad1-445f-b386-b919946339a7" in call_args

    def test_microsoft_365_transform_uses_fallback_guid(self):
        """Test Microsoft 365 transform uses fallback GUID when not found in docs."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "details_ipv4": [], "details_ipv6": [], "source": ""}

        # Mock documentation HTML without GUID
        doc_html = "<html><body>No GUID here</body></html>"

        mock_api_json = [{"id": 1, "serviceArea": "Exchange", "ips": ["23.103.132.0/22"], "category": "Allow"}]

        doc_response = Mock()
        doc_response.text = doc_html

        api_response = Mock()
        api_response.json.return_value = mock_api_json
        api_response.raise_for_status.return_value = None

        cipr.session.get.return_value = api_response

        transform(cipr, [doc_response], "microsoft_365")

        # Should have used fallback GUID
        cipr.session.get.assert_called_once()
        call_args = cipr.session.get.call_args[0][0]
        assert "ClientRequestId=" in call_args

    def test_microsoft_365_transform_with_valid_api_response(self):
        """Test Microsoft 365 transform with valid API response."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "details_ipv4": [], "details_ipv6": [], "source": ""}

        doc_html = "ClientRequestId=test-guid-1234-5678-90ab-cdefghijklmn"

        mock_api_json = [
            {"id": 1, "serviceArea": "Exchange", "ips": ["23.103.132.0/22", "2a01:111:f403::/48"], "category": "Allow"},
            {"id": 2, "serviceArea": "SharePoint", "ips": ["13.107.136.0/22", "2603:1040::/48"], "category": "Optimize"},
        ]

        doc_response = Mock()
        doc_response.text = doc_html

        api_response = Mock()
        api_response.json.return_value = mock_api_json
        api_response.raise_for_status.return_value = None

        cipr.session.get.return_value = api_response

        result = transform(cipr, [doc_response], "microsoft_365")

        # Should extract both IPv4 and IPv6
        assert len(result["ipv4"]) == 2
        assert len(result["ipv6"]) == 2
        assert "23.103.132.0/22" in result["ipv4"]
        assert "13.107.136.0/22" in result["ipv4"]
        assert "2a01:111:f403::/48" in result["ipv6"]
        assert "2603:1040::/48" in result["ipv6"]

    def test_microsoft_365_transform_preserves_metadata(self):
        """Test that Microsoft 365 transform preserves service area metadata."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "details_ipv4": [], "details_ipv6": [], "source": ""}

        doc_html = "ClientRequestId=test-guid-1234-5678-90ab-cdefghijklmn"

        mock_api_json = [{"id": 1, "serviceArea": "Exchange", "ips": ["23.103.132.0/22"], "category": "Allow"}]

        doc_response = Mock()
        doc_response.text = doc_html

        api_response = Mock()
        api_response.json.return_value = mock_api_json
        api_response.raise_for_status.return_value = None

        cipr.session.get.return_value = api_response

        result = transform(cipr, [doc_response], "microsoft_365")

        # Check details include service area
        assert len(result["details_ipv4"]) == 1
        assert result["details_ipv4"][0]["serviceArea"] == "Exchange"
        assert result["details_ipv4"][0]["category"] == "Allow"

    def test_microsoft_365_transform_handles_empty_ips(self):
        """Test Microsoft 365 transform handles endpoint sets without IPs."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "details_ipv4": [], "details_ipv6": [], "source": ""}

        doc_html = "ClientRequestId=test-guid-1234-5678-90ab-cdefghijklmn"

        mock_api_json = [
            {"id": 1, "serviceArea": "Exchange", "urls": ["*.office.com"], "category": "Allow"},
            {"id": 2, "serviceArea": "Common", "ips": ["40.96.0.0/13"], "category": "Default"},
        ]

        doc_response = Mock()
        doc_response.text = doc_html

        api_response = Mock()
        api_response.json.return_value = mock_api_json
        api_response.raise_for_status.return_value = None

        cipr.session.get.return_value = api_response

        result = transform(cipr, [doc_response], "microsoft_365")

        # Should only have the entry with IPs
        assert len(result["ipv4"]) == 1
        assert "40.96.0.0/13" in result["ipv4"]

    def test_microsoft_365_transform_deduplicates_ips(self):
        """Test Microsoft 365 transform deduplicates duplicate IPs."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "details_ipv4": [], "details_ipv6": [], "source": ""}

        doc_html = "ClientRequestId=test-guid-1234-5678-90ab-cdefghijklmn"

        mock_api_json = [
            {"id": 1, "serviceArea": "Exchange", "ips": ["23.103.132.0/22", "23.103.132.0/22"], "category": "Allow"},
            {"id": 2, "serviceArea": "SharePoint", "ips": ["23.103.132.0/22"], "category": "Optimize"},
        ]

        doc_response = Mock()
        doc_response.text = doc_html

        api_response = Mock()
        api_response.json.return_value = mock_api_json
        api_response.raise_for_status.return_value = None

        cipr.session.get.return_value = api_response

        result = transform(cipr, [doc_response], "microsoft_365")

        # Should deduplicate
        assert len(result["ipv4"]) == 1
        assert result["ipv4"][0] == "23.103.132.0/22"
