from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    data = response[0].json()
    result["source_updated_at"] = data.get("modified") or data.get("updated") or data.get("generated")

    for cidr in cipr._extract_cidrs_from_json(data):
        if ":" in cidr:
            result["ipv6"].append(cidr)
        else:
            result["ipv4"].append(cidr)
    return result
