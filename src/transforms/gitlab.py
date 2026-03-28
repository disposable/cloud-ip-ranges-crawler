import re
import ipaddress
from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform GitLab.com Web/API fleet IP ranges from documentation.

    GitLab publishes dedicated Web/API CIDRs for traffic such as webhooks and
    repository mirroring. The ranges are 34.74.90.64/28 and 34.74.226.0/24.

    Reference: https://docs.gitlab.com/user/gitlab_com/

    Note: GitLab-hosted runners do NOT have static egress IPs, so this source
    only covers the documented Web/API fleet, not runner traffic.
    """
    result = cipr._transform_base(source_key)
    result["coverage_notes"] = "GitLab.com Web/API fleet ranges only. GitLab-hosted runners do not have static egress IPs."

    # Hardcoded known ranges from GitLab documentation
    # These are extracted from https://docs.gitlab.com/user/gitlab_com/
    # The ranges are solely allocated to GitLab
    known_ranges = [
        "34.74.90.64/28",
        "34.74.226.0/24",
    ]

    # Also try to extract from the HTML page in case documentation is updated
    try:
        html_content = response[0].text if response else ""

        # Look for IPv4 CIDR patterns (e.g., 192.168.1.0/24)
        cidr4_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}")
        found_cidrs = cidr4_pattern.findall(html_content)

        # Look for IPv6 CIDR patterns (e.g., 2001:db8::/32)
        cidr6_pattern = re.compile(r"[0-9a-fA-F:]+::?[0-9a-fA-F:]*/\d{1,3}")
        found_cidrs.extend(cidr6_pattern.findall(html_content))

        # Look for individual IPv4 addresses (e.g., 192.168.1.1)
        ip4_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        for ip in ip4_pattern.findall(html_content):
            found_cidrs.append(f"{ip}/32")

        # Look for individual IPv6 addresses (e.g., 2001:db8::1)
        ip6_pattern = re.compile(r"\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}\b")
        for ip in ip6_pattern.findall(html_content):
            found_cidrs.append(f"{ip}/128")

        # Validate and use found ranges
        for cidr in found_cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
                if cidr not in known_ranges:
                    known_ranges.append(cidr)
            except ValueError:
                continue
            except Exception:
                pass  # nosec B110 - Intentional fall back to known ranges

    except Exception:
        pass  # nosec B110 - Fall back to known ranges if HTML parsing fails

    for cidr in known_ranges:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if isinstance(network, ipaddress.IPv4Network):
                result["ipv4"].append(str(network))
            elif isinstance(network, ipaddress.IPv6Network):
                result["ipv6"].append(str(network))
        except ValueError:
            continue

    return result
