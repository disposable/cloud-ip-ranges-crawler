from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform STACKIT IP ranges API response."""
    result = cipr._transform_base(source_key)

    try:
        # Try JSON first (primary method)
        data = response[0].json()

        # STACKIT API likely returns IPv4 and IPv6 ranges
        # Handle common JSON structures
        if "prefixes" in data:
            for prefix in data["prefixes"]:
                ip_range = prefix.get("prefix", "") or prefix.get("cidr", "")
                if not ip_range:
                    continue

                if ":" in ip_range:
                    result["ipv6"].append(ip_range)
                else:
                    result["ipv4"].append(ip_range)

        # Check for direct arrays
        elif "ipv4" in data or "ipv6" in data:
            if "ipv4" in data:
                result["ipv4"].extend(data["ipv4"])
            if "ipv6" in data:
                result["ipv6"].extend(data["ipv6"])

        # Check for nested result structure
        elif "result" in data:
            result_data = data["result"]
            if "prefixes" in result_data:
                for prefix in result_data["prefixes"]:
                    ip_range = prefix.get("prefix", "") or prefix.get("cidr", "")
                    if not ip_range:
                        continue
                    if ":" in ip_range:
                        result["ipv6"].append(ip_range)
                    else:
                        result["ipv4"].append(ip_range)
            elif "ipv4" in result_data or "ipv6" in result_data:
                if "ipv4" in result_data:
                    result["ipv4"].extend(result_data["ipv4"])
                if "ipv6" in result_data:
                    result["ipv6"].extend(result_data["ipv6"])

    except (ValueError, AttributeError, KeyError):
        # Fallback: try to parse as text if JSON fails
        try:
            text_content = response[0].text
            import re

            cidr_pattern = r"([0-9]{1,3}(?:\.[0-9]{1,3}){3}/[0-9]{1,2}|[0-9a-fA-F:]+/[0-9]{1,2})"
            cidrs = re.findall(cidr_pattern, text_content)

            for cidr in cidrs:
                cidr = cidr.strip()
                if not cidr:
                    continue

                if ":" in cidr:
                    if re.match(r"^[0-9a-fA-F:]+/[0-9]{1,2}$", cidr):
                        result["ipv6"].append(cidr)
                else:
                    if re.match(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}/[0-9]{1,2}$", cidr):
                        result["ipv4"].append(cidr)
        except Exception:
            raise ValueError("Failed to parse STACKIT response as JSON or text")

    # If we couldn't find any IPs, raise an error
    if not result["ipv4"] and not result["ipv6"]:
        raise ValueError("Failed to parse STACKIT response as JSON or text")

    return result
