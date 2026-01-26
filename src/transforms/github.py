from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    result["details_ipv4"] = []
    result["details_ipv6"] = []
    data = response[0].json()

    if isinstance(data, dict):
        for key in ["hooks", "web"]:
            ranges = data.get(key, [])
            for r in ranges:
                if ":" in r:
                    result["ipv6"].append(r)
                    result["details_ipv6"].append({"address": r, "category": key})
                else:
                    result["ipv4"].append(r)
                    result["details_ipv4"].append({"address": r, "category": key})

    return result
