"""GitLab.com Web/API fleet IP ranges transform.

SCOPE: This transform ONLY extracts the GitLab.com Web/API fleet IP ranges
that are documented for webhook and repository mirroring traffic.

INTENDED RANGES:
- 34.74.90.64/28 (solely allocated to GitLab)
- 34.74.226.0/24 (solely allocated to GitLab)

EXPLICITLY OUT OF SCOPE:
- GitLab-hosted runners (do NOT have static egress IPs)
- Any other IP ranges mentioned elsewhere on the docs page
- IPv6 ranges (not documented for Web/API fleet)

APPROACH: Conservative - only hardcoded known ranges are emitted.
HTML extraction is intentionally DISABLED to prevent over-collection.
The GitLab docs page contains many unrelated IPs (Cloudflare, examples, etc.)
that must NOT be collected as Web/API fleet ranges.
"""

import ipaddress
from typing import Any, Dict, List

# Official GitLab.com Web/API fleet ranges
# These are the ONLY ranges documented for webhook/mirroring traffic
# Source: https://docs.gitlab.com/user/gitlab_com/
KNOWN_WEBAPI_RANGES = [
    "34.74.90.64/28",
    "34.74.226.0/24",
]


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform GitLab.com Web/API fleet IP ranges.

    This transform ONLY extracts the documented Web/API fleet ranges.
    It does NOT extract arbitrary IPs from the documentation page.

    GitLab-hosted runners do NOT have static egress IPs - this is explicitly
    out of scope per GitLab's own documentation.
    """
    result = cipr._transform_base(source_key)
    result["coverage_notes"] = (
        "GitLab.com Web/API fleet ranges ONLY (34.74.90.64/28, 34.74.226.0/24). "
        "GitLab-hosted runners do NOT have static egress IPs. "
        "Scope: webhook traffic and repository mirroring only."
    )

    # CONSERVATIVE APPROACH: Use only hardcoded known ranges
    # HTML extraction is intentionally disabled to prevent over-collection.
    # The GitLab docs page contains many unrelated IPs (Cloudflare, examples, etc.)
    # that must NOT be collected as Web/API fleet ranges.
    # See: https://docs.gitlab.com/user/gitlab_com/
    webapi_ranges = list(KNOWN_WEBAPI_RANGES)

    # Note: If GitLab updates their documented ranges, this constant must be updated.
    # This is intentional - we'd rather miss new ranges than collect unrelated IPs.

    # Validate and categorize ranges
    for cidr in webapi_ranges:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if isinstance(network, ipaddress.IPv4Network):
                result["ipv4"].append(str(network))
            # Note: IPv6 ranges are not documented for Web/API fleet
        except ValueError:
            continue

    return result


def _extract_webapi_section(html: str) -> str:
    """Extract the Web/API fleet section from HTML - DISABLED.

    NOTE: This function is intentionally not used. HTML extraction is disabled
    to prevent over-collection of unrelated IPs from the documentation page.

    The GitLab docs contain many IPs that are NOT Web/API fleet ranges:
    - Cloudflare IPs (for CDN/proxy)
    - Example/documentation IPs
    - Other service IPs

    We prefer under-collection over accidental over-collection.
    Only KNOWN_WEBAPI_RANGES are emitted.
    """
    return ""


def _extract_cidrs_from_section(section: str) -> List[str]:
    """Extract CIDRs from a specific HTML section - DISABLED.

    NOTE: This function is intentionally not used.
    See _extract_webapi_section for rationale.
    """
    return []


def _is_valid_webapi_cidr(cidr: str) -> bool:
    """Check if a CIDR is valid - DISABLED (not used).

    NOTE: This function is intentionally not used.
    See _extract_webapi_section for rationale.
    """
    return False
