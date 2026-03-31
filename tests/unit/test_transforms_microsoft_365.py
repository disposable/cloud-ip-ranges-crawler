"""Microsoft 365 endpoints web service transform tests.

These tests verify the proper web service flow:
1. Local UUID generation (NOT scraped from docs)
2. Version endpoint checking
3. Endpoints fetching with full metadata preservation
"""

from unittest.mock import Mock
from transforms.microsoft_365 import transform


class TestMicrosoft365Transform:
    """Test Microsoft 365 proper web service flow."""

    def test_microsoft_365_generates_local_uuid(self):
        """Test that transform generates UUID locally, NOT from docs/examples."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "details_ipv4": [], "details_ipv6": [], "source": "", "source_updated_at": None}

        # Mock version response
        version_response = Mock()
        version_response.json.return_value = {"latest": "2026032800"}
        version_response.raise_for_status.return_value = None

        # Mock endpoints response
        endpoints_response = Mock()
        endpoints_response.json.return_value = [
            {"id": 1, "serviceArea": "Exchange", "ips": ["23.103.132.0/22"], "category": "Allow", "required": True, "tcpPorts": "443"}
        ]
        endpoints_response.raise_for_status.return_value = None

        # Track calls made to session.get
        calls_made = []

        def mock_get(url, **kwargs):
            calls_made.append(url)
            if "/version/" in url:
                return version_response
            elif "/endpoints/" in url:
                return endpoints_response
            return Mock()

        cipr.session.get = mock_get

        # Mock input response (can be anything, we don't scrape it anymore)
        input_response = [Mock()]
        input_response[0].text = "Some documentation HTML with example ClientRequestId=example-guid-1234"

        transform(cipr, input_response, "microsoft_365")

        # Verify UUID was generated locally (should be valid UUID format)
        assert len(calls_made) >= 1

        # Check that the URLs use a proper UUID (not the example one)
        for url in calls_made:
            # Should contain clientrequestid parameter
            assert "clientrequestid=" in url.lower()
            # Should NOT contain the example GUID from the docs
            assert "example-guid-1234" not in url

    def test_microsoft_365_checks_version_endpoint_first(self):
        """Test that transform checks version endpoint before fetching endpoints."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "details_ipv4": [], "details_ipv6": [], "source": "", "source_updated_at": None}

        version_response = Mock()
        version_response.json.return_value = {"latest": "2026032801"}
        version_response.raise_for_status.return_value = None

        endpoints_response = Mock()
        endpoints_response.json.return_value = [{"id": 1, "serviceArea": "Exchange", "ips": ["23.103.132.0/22"], "category": "Allow"}]
        endpoints_response.raise_for_status.return_value = None

        call_order = []

        def mock_get(url, **kwargs):
            call_order.append(url)
            if "/version/" in url:
                return version_response
            elif "/endpoints/" in url:
                return endpoints_response
            return Mock()

        cipr.session.get = mock_get

        input_response = [Mock()]
        input_response[0].text = ""

        result = transform(cipr, input_response, "microsoft_365")

        # Version should be checked first
        assert len(call_order) >= 2
        assert "/version/" in call_order[0]
        assert "/endpoints/" in call_order[1]

        # Version should be recorded
        assert result["source_updated_at"] == "2026032801"

    def test_microsoft_365_preserves_full_metadata(self):
        """Test that transform preserves complete endpoint metadata."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "details_ipv4": [], "details_ipv6": [], "source": "", "source_updated_at": None}

        version_response = Mock()
        version_response.json.return_value = {"latest": "2026032802"}
        version_response.raise_for_status.return_value = None

        endpoints_response = Mock()
        endpoints_response.json.return_value = [
            {"id": 42, "serviceArea": "Exchange", "category": "Allow", "required": True, "tcpPorts": "443,993", "udpPorts": "", "ips": ["23.103.132.0/22"]},
            {
                "id": 43,
                "serviceArea": "Skype",
                "category": "Default",
                "required": False,
                "tcpPorts": "443",
                "udpPorts": "3478",
                "ips": ["13.107.64.0/18", "2a01:111:f100::/48"],
            },
        ]
        endpoints_response.raise_for_status.return_value = None

        def mock_get(url, **kwargs):
            if "/version/" in url:
                return version_response
            elif "/endpoints/" in url:
                return endpoints_response
            return Mock()

        cipr.session.get = mock_get

        input_response = [Mock()]
        input_response[0].text = ""

        result = transform(cipr, input_response, "microsoft_365")

        # Check metadata is preserved for IPv4
        ipv4_details = result["details_ipv4"]
        assert len(ipv4_details) == 2  # One from Exchange, one from Skype

        exchange_detail = [d for d in ipv4_details if d["serviceArea"] == "Exchange"][0]
        assert exchange_detail["address"] == "23.103.132.0/22"
        assert exchange_detail["endpointId"] == 42
        assert exchange_detail["category"] == "Allow"
        assert exchange_detail["required"] == True
        assert exchange_detail["tcpPorts"] == "443,993"

        skype_detail = [d for d in ipv4_details if d["serviceArea"] == "Skype"][0]
        assert skype_detail["address"] == "13.107.64.0/18"
        assert skype_detail["endpointId"] == 43
        assert skype_detail["udpPorts"] == "3478"

        # Check IPv6 metadata
        ipv6_details = result["details_ipv6"]
        assert len(ipv6_details) == 1
        assert ipv6_details[0]["address"] == "2a01:111:f100::/48"
        assert ipv6_details[0]["serviceArea"] == "Skype"

    def test_microsoft_365_handles_version_check_failure(self):
        """Test that transform continues even if version check fails."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "details_ipv4": [], "details_ipv6": [], "source": "", "source_updated_at": None}

        # Version check fails
        def mock_get(url, **kwargs):
            if "/version/" in url:
                raise Exception("Version check failed")
            elif "/endpoints/" in url:
                endpoints_response = Mock()
                endpoints_response.json.return_value = [{"id": 1, "serviceArea": "Exchange", "ips": ["23.103.132.0/22"], "category": "Allow"}]
                endpoints_response.raise_for_status.return_value = None
                return endpoints_response
            return Mock()

        cipr.session.get = mock_get

        input_response = [Mock()]
        input_response[0].text = ""

        # Should not raise - proceeds to fetch endpoints
        result = transform(cipr, input_response, "microsoft_365")

        # Should still have data from endpoints
        assert len(result["ipv4"]) == 1
        assert "23.103.132.0/22" in result["ipv4"]

    def test_microsoft_365_fails_on_invalid_endpoint_response(self):
        """Test that transform fails clearly on invalid endpoint response."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "details_ipv4": [], "details_ipv6": [], "source": "", "source_updated_at": None}

        version_response = Mock()
        version_response.json.return_value = {"latest": "2026032803"}
        version_response.raise_for_status.return_value = None

        # Invalid response (not an array)
        endpoints_response = Mock()
        endpoints_response.json.return_value = {"error": "not found"}
        endpoints_response.raise_for_status.return_value = None

        def mock_get(url, **kwargs):
            if "/version/" in url:
                return version_response
            elif "/endpoints/" in url:
                return endpoints_response
            return Mock()

        cipr.session.get = mock_get

        input_response = [Mock()]
        input_response[0].text = ""

        # Should raise with clear error message
        try:
            transform(cipr, input_response, "microsoft_365")
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Expected JSON array" in str(e)

    def test_microsoft_365_coverage_notes_explicit(self):
        """Test that coverage notes explicitly state scope."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "details_ipv4": [], "details_ipv6": [], "source": "", "source_updated_at": None}

        version_response = Mock()
        version_response.json.return_value = {"latest": "2026032804"}
        version_response.raise_for_status.return_value = None

        endpoints_response = Mock()
        endpoints_response.json.return_value = []
        endpoints_response.raise_for_status.return_value = None

        def mock_get(url, **kwargs):
            if "/version/" in url:
                return version_response
            elif "/endpoints/" in url:
                return endpoints_response
            return Mock()

        cipr.session.get = mock_get

        input_response = [Mock()]
        input_response[0].text = ""

        result = transform(cipr, input_response, "microsoft_365")

        # Should be explicit about scope
        assert "Microsoft 365" in result["coverage_notes"]
        assert "Worldwide" in result["coverage_notes"] or "instance" in result["coverage_notes"]
        assert "Azure" in result["coverage_notes"] and "NOT" in result["coverage_notes"]

    def test_microsoft_365_skips_endpoint_sets_without_ips(self):
        """Test that endpoint sets without 'ips' field are skipped."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "details_ipv4": [], "details_ipv6": [], "source": "", "source_updated_at": None}

        version_response = Mock()
        version_response.json.return_value = {"latest": "2026032805"}
        version_response.raise_for_status.return_value = None

        endpoints_response = Mock()
        endpoints_response.json.return_value = [
            {"id": 1, "serviceArea": "Exchange", "urls": ["*.office.com"], "category": "Allow"},  # No IPs
            {"id": 2, "serviceArea": "Common", "ips": ["40.96.0.0/13"], "category": "Default"},  # Has IPs
        ]
        endpoints_response.raise_for_status.return_value = None

        def mock_get(url, **kwargs):
            if "/version/" in url:
                return version_response
            elif "/endpoints/" in url:
                return endpoints_response
            return Mock()

        cipr.session.get = mock_get

        input_response = [Mock()]
        input_response[0].text = ""

        result = transform(cipr, input_response, "microsoft_365")

        # Should only have the one with IPs
        assert len(result["ipv4"]) == 1
        assert "40.96.0.0/13" in result["ipv4"]

    def test_microsoft_365_deduplicates_ips(self):
        """Test that duplicate IPs are deduplicated."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "details_ipv4": [], "details_ipv6": [], "source": "", "source_updated_at": None}

        version_response = Mock()
        version_response.json.return_value = {"latest": "2026032806"}
        version_response.raise_for_status.return_value = None

        endpoints_response = Mock()
        endpoints_response.json.return_value = [
            {"id": 1, "serviceArea": "Exchange", "ips": ["23.103.132.0/22", "23.103.132.0/22"], "category": "Allow"},
            {"id": 2, "serviceArea": "SharePoint", "ips": ["23.103.132.0/22"], "category": "Optimize"},
        ]
        endpoints_response.raise_for_status.return_value = None

        def mock_get(url, **kwargs):
            if "/version/" in url:
                return version_response
            elif "/endpoints/" in url:
                return endpoints_response
            return Mock()

        cipr.session.get = mock_get

        input_response = [Mock()]
        input_response[0].text = ""

        result = transform(cipr, input_response, "microsoft_365")

        # Should deduplicate - same IP appears twice in Exchange, once in SharePoint
        assert len(result["ipv4"]) == 1
        assert result["ipv4"][0] == "23.103.132.0/22"

        # But details should preserve all entries (with different metadata)
        assert len(result["details_ipv4"]) == 3  # Two Exchange + one SharePoint

    def test_microsoft_365_source_stable_source_http_contains_urls(self):
        """Test that source is stable (docs URL) and source_http has the UUID URLs.

        This is critical for change detection - source must be stable across runs.
        """
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "details_ipv4": [], "details_ipv6": [], "source": "", "source_updated_at": None}

        version_response = Mock()
        version_response.json.return_value = {"latest": "2026032807"}
        version_response.raise_for_status.return_value = None

        endpoints_response = Mock()
        endpoints_response.json.return_value = []
        endpoints_response.raise_for_status.return_value = None

        def mock_get(url, **kwargs):
            if "/version/" in url:
                return version_response
            elif "/endpoints/" in url:
                return endpoints_response
            return Mock()

        cipr.session.get = mock_get

        input_response = [Mock()]
        input_response[0].text = ""

        result = transform(cipr, input_response, "microsoft_365")

        # Source should be stable documentation URL (no UUID)
        assert result["source"] == "https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service"

        # source_http should contain the actual API URLs with UUIDs
        assert "source_http" in result
        assert isinstance(result["source_http"], list)
        assert len(result["source_http"]) == 2
        assert any("/version/" in s for s in result["source_http"])
        assert any("/endpoints/" in s for s in result["source_http"])
        # URLs should have UUIDs (clientrequestid parameter)
        assert all("clientrequestid=" in s.lower() for s in result["source_http"])
