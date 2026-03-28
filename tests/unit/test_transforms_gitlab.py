"""GitLab Web/API fleet transform tests.

These tests verify that the GitLab transform ONLY extracts the documented
Web/API fleet ranges and does NOT over-collect unrelated IPs from the page.
"""

from unittest.mock import Mock
from transforms.gitlab import transform, KNOWN_WEBAPI_RANGES


class TestGitlabTransform:
    """Test GitLab Web/API fleet range extraction."""

    def test_gitlab_transform_returns_only_known_ranges_by_default(self):
        """Test that transform returns only the documented Web/API fleet ranges."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        response = [Mock()]
        response[0].text = ""  # Empty HTML, should use known ranges

        result = transform(cipr, response, "gitlab")

        # Should ONLY have the two documented Web/API fleet ranges
        assert len(result["ipv4"]) == 2
        assert "34.74.90.64/28" in result["ipv4"]
        assert "34.74.226.0/24" in result["ipv4"]
        # No IPv6 for Web/API fleet
        assert len(result["ipv6"]) == 0

    def test_gitlab_transform_does_not_over_collect_unrelated_ips(self):
        """Test that transform does NOT extract IPs from HTML - only hardcoded ranges.

        This is the key regression test - the page contains many other IPs
        (Cloudflare IPs, documentation examples, etc.) that must NOT be
        collected as GitLab Web/API fleet ranges.

        With the conservative approach, HTML extraction is disabled entirely.
        """
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        # HTML containing Web/API fleet section AND unrelated IPs
        response = [Mock()]
        response[0].text = """
        <html>
        <body>
        <h1>GitLab.com Settings</h1>

        <h2>Cloudflare Integration</h2>
        <p>GitLab.com uses Cloudflare IPs like 104.16.0.0/12 and 162.158.0.0/16</p>

        <h2>Web/API fleet</h2>
        <p>The following IP ranges are solely allocated to GitLab for Web/API traffic:</p>
        <ul>
        <li>34.74.90.64/28</li>
        <li>34.74.226.0/24</li>
        </ul>
        <p>These ranges are used for webhook traffic and repository mirroring.</p>

        <h2>Other Services</h2>
        <p>Some other services use 192.168.1.0/24 or 10.0.0.0/8</p>
        </body>
        </html>
        """

        result = transform(cipr, response, "gitlab")

        # Should ONLY have the two hardcoded Web/API fleet ranges
        # HTML extraction is disabled - no IPs are extracted from the page
        assert len(result["ipv4"]) == 2
        assert "34.74.90.64/28" in result["ipv4"]
        assert "34.74.226.0/24" in result["ipv4"]

        # These should NOT be present - HTML extraction disabled
        assert "104.16.0.0/12" not in result["ipv4"]
        assert "162.158.0.0/16" not in result["ipv4"]
        assert "192.168.1.0/24" not in result["ipv4"]
        assert "10.0.0.0/8" not in result["ipv4"]

    def test_gitlab_transform_no_ipv6(self):
        """Test that GitLab Web/API fleet does not include IPv6.

        GitLab does not document IPv6 ranges for Web/API fleet.
        """
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        response = [Mock()]
        response[0].text = """
        <p>IPv6 range: 2001:db8::/32</p>
        <p>Web/API: 34.74.90.64/28 solely allocated to GitLab</p>
        """

        result = transform(cipr, response, "gitlab")

        # Should have IPv4 Web/API range
        assert "34.74.90.64/28" in result["ipv4"]
        # Should NOT have IPv6 - not documented for Web/API fleet
        assert "2001:db8::/32" not in result["ipv6"]
        assert len(result["ipv6"]) == 0

    def test_gitlab_transform_coverage_notes_explicit(self):
        """Test that coverage notes are explicit about scope limitations."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        response = [Mock()]
        response[0].text = ""

        result = transform(cipr, response, "gitlab")

        # Should explicitly mention Web/API fleet and runner limitation
        assert "Web/API fleet" in result["coverage_notes"]
        assert "34.74.90.64/28" in result["coverage_notes"] or "34.74.226.0/24" in result["coverage_notes"]
        assert "runners" in result["coverage_notes"]
        assert "do NOT have static" in result["coverage_notes"]

    def test_gitlab_transform_section_aware_parsing(self):
        """Test that HTML parsing is disabled - only hardcoded ranges are used.

        Even with CIDRs in various sections, only the KNOWN_WEBAPI_RANGES
        should be returned.
        """
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        # HTML with CIDRs everywhere
        response = [Mock()]
        response[0].text = """
        <div class="other">
            <p>Some random IP: 192.168.5.0/24</p>
        </div>
        <div class="webapi">
            <p>Web/API fleet ranges solely allocated to GitLab:</p>
            <p>34.74.90.64/28</p>
        </div>
        <div class="other">
            <p>Another random IP: 10.20.30.0/24</p>
        </div>
        """

        result = transform(cipr, response, "gitlab")

        # Should only have the hardcoded ranges - HTML extraction disabled
        assert len(result["ipv4"]) == 2
        assert "34.74.90.64/28" in result["ipv4"]
        assert "34.74.226.0/24" in result["ipv4"]
        assert "192.168.5.0/24" not in result["ipv4"]
        assert "10.20.30.0/24" not in result["ipv4"]

    def test_gitlab_known_ranges_constant(self):
        """Test that KNOWN_WEBAPI_RANGES contains expected values."""
        assert len(KNOWN_WEBAPI_RANGES) == 2
        assert "34.74.90.64/28" in KNOWN_WEBAPI_RANGES
        assert "34.74.226.0/24" in KNOWN_WEBAPI_RANGES

    def test_gitlab_transform_validates_cidr_prefix(self):
        """Test that only hardcoded ranges are used regardless of HTML content.

        With HTML extraction disabled, this test verifies that even "valid-looking"
        CIDRs in the HTML are NOT collected.
        """
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        # Try to sneak in an invalid prefix
        response = [Mock()]
        response[0].text = """
        <p>Web/API fleet solely allocated to GitLab:</p>
        <p>8.0.0.0/8</p>  <!-- Too broad, but also should be ignored entirely -->
        <p>34.74.90.64/28</p>
        """

        result = transform(cipr, response, "gitlab")

        # Should only have the hardcoded ranges - HTML extraction disabled
        assert len(result["ipv4"]) == 2
        assert "34.74.90.64/28" in result["ipv4"]
        assert "34.74.226.0/24" in result["ipv4"]
        assert "8.0.0.0/8" not in result["ipv4"]
