from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform Exoscale JSON IP ranges feed."""
    result = cipr._transform_base(source_key)

    try:
        data = response[0].json()

        # Exoscale provides IPv4 and IPv6 ranges in their JSON format
        if "prefixes" in data:
            for prefix in data["prefixes"]:
                # Check for IPv4Prefix or IPv6Prefix fields
                ipv4_prefix = prefix.get("IPv4Prefix", "")
                ipv6_prefix = prefix.get("IPv6Prefix", "")

                if ipv4_prefix:
                    result["ipv4"].append(ipv4_prefix)
                if ipv6_prefix:
                    result["ipv6"].append(ipv6_prefix)

                # Fallback to generic 'prefix' field
                generic_prefix = prefix.get("prefix", "")
                if generic_prefix:
                    if ":" in generic_prefix:
                        result["ipv6"].append(generic_prefix)
                    else:
                        result["ipv4"].append(generic_prefix)

                # Also check for 'cidr' field
                cidr_prefix = prefix.get("cidr", "")
                if cidr_prefix:
                    if ":" in cidr_prefix:
                        result["ipv6"].append(cidr_prefix)
                    else:
                        result["ipv4"].append(cidr_prefix)

        # Also check for direct ipv4/ipv6 arrays as fallback
        else:
            if "ipv4" in data:
                result["ipv4"].extend(data["ipv4"])
            if "ipv6" in data:
                result["ipv6"].extend(data["ipv6"])

        # Remove empty strings and deduplicate
        result["ipv4"] = [ip for ip in result["ipv4"] if ip]
        result["ipv6"] = [ip for ip in result["ipv6"] if ip]

    except (ValueError, AttributeError, KeyError) as e:
        raise ValueError(f"Failed to parse Exoscale JSON response: {e}")

    return result
