import re
from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform Cisco Webex HTML network requirements to extract media CIDR ranges."""
    result = cipr._transform_base(source_key)

    try:
        # Handle multiple Webex pages (media and meetings)
        all_content = ""
        for resp in response:
            all_content += resp.text + "\n"

        # Webex lists IP ranges for media services
        # Look for CIDR patterns in the HTML content
        cidr_pattern = r"([0-9]{1,3}(?:\.[0-9]{1,3}){3}/[0-9]{1,2}|[0-9a-fA-F:]+/[0-9]{1,2})"

        # Find all CIDR blocks
        cidrs = re.findall(cidr_pattern, all_content)

        for cidr in cidrs:
            cidr = cidr.strip()
            if not cidr:
                continue

            # Validate and categorize as IPv4 or IPv6
            if ":" in cidr:
                # Basic IPv6 validation - prefix length must be 1-128
                if re.match(r"^[0-9a-fA-F:]+/([1-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$", cidr):
                    result["ipv6"].append(cidr)
            else:
                # Basic IPv4 validation - prefix length must be 1-32
                if re.match(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}/([1-9]|[1-2][0-9]|3[0-2])$", cidr):
                    # Additional validation for octet ranges
                    octets = cidr.split("/")[0].split(".")
                    if all(0 <= int(octet) <= 255 for octet in octets):
                        result["ipv4"].append(cidr)

    except Exception as e:
        raise ValueError(f"Failed to parse Cisco Webex HTML response: {e}")

    return result
