from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    result["details_ipv4"] = []
    result["details_ipv6"] = []

    required_data = response[0].json()
    if isinstance(required_data, dict) and "hubPrefixes" in required_data:
        for prefix in required_data["hubPrefixes"]:
            if ":" in prefix:
                result["ipv6"].append(prefix)
                result["details_ipv6"].append({"address": prefix, "category": "required"})
            else:
                result["ipv4"].append(prefix)
                result["details_ipv4"].append({"address": prefix, "category": "required"})

    recommended_data = response[1].json()
    if isinstance(recommended_data, dict) and "hubPrefixes" in recommended_data:
        for prefix in recommended_data["hubPrefixes"]:
            if ":" in prefix:
                result["ipv6"].append(prefix)
                result["details_ipv6"].append({"address": prefix, "category": "recommended"})
            else:
                result["ipv4"].append(prefix)
                result["details_ipv4"].append({"address": prefix, "category": "recommended"})

    return result
