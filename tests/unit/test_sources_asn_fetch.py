from unittest.mock import Mock

from src.sources.asn import fetch_and_save_asn_source


class _MockResponse:
    def __init__(self, json_data=None, text_data="", status_code=200, headers=None, url="https://example.com"):
        self._json_data = json_data or {}
        self.text = text_data
        self.status_code = status_code
        self.headers = headers or {}
        self.url = url

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception("HTTP error")


def _make_cipr(prefixes_by_asn: dict[str, list[str]]):
    cipr = Mock()
    cipr.session = Mock()
    cipr.session.get = Mock(side_effect=AssertionError("session.get should not be called"))

    def _base_return(source_key, urls):
        return {"ipv4": [], "ipv6": []}

    cipr._transform_base.side_effect = _base_return
    cipr._normalize_transformed_data.side_effect = lambda data, source_key: data

    def _ripestat_side_effect(asn: str):
        prefixes = prefixes_by_asn.get(asn, [])
        resp = _MockResponse(
            json_data={
                "data": {
                    "queried_at": "2025-01-29T00:00:00Z",
                    "prefixes": [{"prefix": p} for p in prefixes],
                }
            },
            headers={"content-type": "application/json"},
            url=f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}",
        )
        return resp.url, resp

    cipr.ripestat_fetch.side_effect = _ripestat_side_effect
    return cipr


class TestNewASNSources:
    def test_upcloud_asn_source(self):
        """Test UpCloud ASN source with multiple ASNs."""
        cipr = _make_cipr({"AS202053": ["185.1.2.0/24"], "AS25697": ["2a01:1:2::/48"]})
        result = fetch_and_save_asn_source(cipr, "upcloud", ["AS202053", "AS25697"])

        assert "ipv4" in result
        assert result["method"] == "bgp_announced"
        assert "ipv6" in result
        assert len(result["source_http"]) == 2  # Two ASNs

    def test_gridscale_asn_source(self):
        """Test gridscale ASN source."""
        cipr = _make_cipr({"AS29423": ["85.236.32.0/19"]})
        result = fetch_and_save_asn_source(cipr, "gridscale", ["AS29423"])

        assert "ipv4" in result
        assert result["method"] == "bgp_announced"

    def test_wasabi_asn_source(self):
        """Test Wasabi ASN source."""
        cipr = _make_cipr({"AS395717": ["45.11.36.0/22"]})
        result = fetch_and_save_asn_source(cipr, "wasabi", ["AS395717"])

        assert "ipv4" in result
        assert result["method"] == "bgp_announced"

    def test_ionos_cloud_asn_source(self):
        """Test IONOS Cloud ASN source."""
        cipr = _make_cipr({"AS8560": ["212.224.0.0/16"]})
        result = fetch_and_save_asn_source(cipr, "ionos_cloud", ["AS8560"])

        assert "ipv4" in result
        assert result["method"] == "bgp_announced"

    def test_open_telekom_cloud_asn_source(self):
        """Test Open Telekom Cloud ASN source."""
        cipr = _make_cipr({"AS6878": ["80.158.0.0/16"]})
        result = fetch_and_save_asn_source(cipr, "open_telekom_cloud", ["AS6878"])

        assert "ipv4" in result
        assert result["method"] == "bgp_announced"

    def test_kamatera_asn_source(self):
        """Test Kamatera ASN source."""
        cipr = _make_cipr({"AS36007": ["185.4.0.0/16"]})
        result = fetch_and_save_asn_source(cipr, "kamatera", ["AS36007"])

        assert "ipv4" in result
        assert result["method"] == "bgp_announced"

    def test_ripestat_fallback_to_hackertarget(self):
        """Test fallback to HackerTarget when RIPEstat fails."""
        cipr = Mock()

        def _mock_normalize(data, source_key):
            return data

        cipr._transform_base.side_effect = lambda source_key, urls: {"ipv4": [], "ipv6": []}
        cipr._normalize_transformed_data.side_effect = _mock_normalize

        # Mock RIPEstat failure
        cipr.ripestat_fetch.side_effect = Exception("RIPEstat failed")

        # Mock HackerTarget success
        hackertarget_response = _MockResponse(
            text_data="""
            AS,IP
            AS395717,45.11.36.0/22
            """,
            headers={"content-type": "text/plain"},
            url="https://api.hackertarget.com/aslookup/?q=AS395717",
        )

        cipr.session = Mock()
        cipr.session.get.return_value = hackertarget_response

        result = fetch_and_save_asn_source(cipr, "wasabi", ["AS395717"])

        assert result["method"] == "asn_lookup"  # Should be fallback method
        assert len(result["source_http"]) == 1  # Only HackerTarget (RIPEstat failed)
