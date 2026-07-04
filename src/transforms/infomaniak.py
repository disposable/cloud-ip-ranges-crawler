from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform Infomaniak JSON IP ranges feed."""
    result = cipr._transform_base(source_key)

    try:
        data = response[0].json()

        # Infomaniak provides categories (ksuite, vps, public-cloud, all).
        # The "all" category is the comprehensive aggregated list.
        if "all" in data and isinstance(data["all"], dict):
            all_data = data["all"]
            if "ipv4" in all_data:
                result["ipv4"].extend(all_data["ipv4"])
            if "ipv6" in all_data:
                result["ipv6"].extend(all_data["ipv6"])
        else:
            # Fallback: collect from all categories
            for category in data.values():
                if isinstance(category, dict):
                    if "ipv4" in category:
                        result["ipv4"].extend(category["ipv4"])
                    if "ipv6" in category:
                        result["ipv6"].extend(category["ipv6"])

        # Filter out non-string entries
        result["ipv4"] = [ip for ip in result["ipv4"] if isinstance(ip, str)]
        result["ipv6"] = [ip for ip in result["ipv6"] if isinstance(ip, str)]

    except (ValueError, AttributeError, KeyError) as e:
        raise ValueError(f"Failed to parse Infomaniak JSON response: {e}") from e

    return result
