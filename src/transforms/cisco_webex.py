import re
import ipaddress
from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform Cisco Webex HTML network requirements to extract media CIDR ranges."""
    result = cipr._transform_base(source_key)

    try:
        # Handle multiple Webex pages (media and meetings)
        all_content = ""
        for resp in response:
            all_content += resp.text + "\n"

        # Extract all text content that might contain IP addresses
        # Look for patterns that could be IP networks (numbers, colons, slashes)
        potential_patterns = re.findall(r"[0-9a-fA-F:.]+/[0-9]{1,3}", all_content)

        # Remove duplicates while preserving order
        seen = set()
        unique_patterns = []
        for pattern in potential_patterns:
            if pattern not in seen:
                seen.add(pattern)
                unique_patterns.append(pattern)

        for content in unique_patterns:
            content = content.strip()
            if not content:
                continue

            # Use ipaddress module to validate and categorize
            try:
                network = ipaddress.ip_network(content, strict=False)

                if isinstance(network, ipaddress.IPv4Network):
                    result["ipv4"].append(str(network))
                elif isinstance(network, ipaddress.IPv6Network):
                    result["ipv6"].append(str(network))
            except ValueError:
                # Not a valid IP network, skip it
                continue

    except Exception as e:
        raise ValueError(f"Failed to parse Cisco Webex HTML response: {e}")

    return result
