"""GitLab transform tests."""

from unittest.mock import Mock
from transforms.gitlab import transform


class TestGitlabTransform:
    def test_gitlab_transform_uses_known_ranges(self):
        """Test GitLab transform uses the hardcoded known ranges."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        response = [Mock()]
        response[0].text = ""  # Empty HTML, should fall back to known ranges

        result = transform(cipr, response, "gitlab")

        # Should have the known GitLab Web/API fleet ranges
        assert len(result["ipv4"]) == 2
        assert "34.74.90.64/28" in result["ipv4"]
        assert "34.74.226.0/24" in result["ipv4"]

    def test_gitlab_transform_extracts_from_html(self):
        """Test GitLab transform extracts CIDRs from HTML if present."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        response = [Mock()]
        response[0].text = """
        GitLab.com uses the IP ranges 192.168.1.0/24 and 10.0.0.0/8 for traffic.
        These are solely allocated to GitLab.
        """

        result = transform(cipr, response, "gitlab")

        # Should include both known ranges and extracted ranges
        assert len(result["ipv4"]) >= 2
        # Should have the known ranges plus extracted ones
        assert "34.74.90.64/28" in result["ipv4"]  # Known range
        assert "192.168.1.0/24" in result["ipv4"]  # Extracted

    def test_gitlab_transform_coverage_notes(self):
        """Test GitLab transform includes appropriate coverage notes."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        response = [Mock()]
        response[0].text = ""

        result = transform(cipr, response, "gitlab")

        # Should note the limitation about runners
        assert "Web/API fleet" in result["coverage_notes"]
        assert "runners" in result["coverage_notes"]

    def test_gitlab_transform_validates_extracted_cidrs(self):
        """Test GitLab transform validates extracted CIDRs."""
        cipr = Mock()
        cipr._transform_base.return_value = {"ipv4": [], "ipv6": [], "coverage_notes": ""}

        response = [Mock()]
        # Include invalid CIDRs that should be filtered out
        response[0].text = """
        Valid: 192.168.1.0/24
        Invalid: 999.999.999.999/99
        Also invalid: not-a-cidr
        """

        result = transform(cipr, response, "gitlab")

        # Should only have valid CIDRs (known + valid extracted)
        for cidr in result["ipv4"]:
            # Each should be parsable as an IP network
            import ipaddress

            ipaddress.ip_network(cidr, strict=False)
