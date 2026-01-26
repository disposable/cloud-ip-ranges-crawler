import re
from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)

    # Branch documentation contains IP ranges in HTML tables
    # Extract CIDR patterns from the HTML content
    text = response[0].text

    # Look for CIDR patterns in the documentation
    # Branch uses /32 for individual IPs and some CIDR ranges
    cidr_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b"
    cidrs = re.findall(cidr_pattern, text)

    # Also look for bare IPs that should be normalized to /32
    # Find IPs that are not already part of a CIDR
    ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
    all_ips = re.findall(ip_pattern, text)

    # Add CIDRs directly
    for cidr in cidrs:
        result["ipv4"].append(cidr)

    # Extract bare IPs from all IPs, excluding those already in CIDRs
    cidr_ips = set()
    for cidr in cidrs:
        # Extract IP part from CIDR (before the slash)
        ip_part = cidr.split("/")[0]
        cidr_ips.add(ip_part)

    # Add bare IPs normalized to /32, excluding those already in CIDRs
    for ip in all_ips:
        if ip not in cidr_ips:
            result["ipv4"].append(f"{ip}/32")

    # Remove duplicates while preserving order
    seen = set()
    unique_ipv4 = []
    for ip in result["ipv4"]:
        if ip not in seen:
            seen.add(ip)
            unique_ipv4.append(ip)

    result["ipv4"] = unique_ipv4

    return result
