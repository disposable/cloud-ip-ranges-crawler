from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    data = response[0].json()
    result["source_updated_at"] = data.get("creationDate") or data.get("created") or data.get("generated")

    items = data.get("items") if isinstance(data, dict) else None
    if isinstance(items, list):
        for it in items:
            if not isinstance(it, dict):
                continue
            cidr = it.get("cidr") or it.get("ip") or it.get("prefix")
            if not cidr or not isinstance(cidr, str):
                continue
            if ":" in cidr:
                result["ipv6"].append(cidr)
            else:
                result["ipv4"].append(cidr)
        return result

    for cidr in cipr._extract_cidrs_from_json(data):
        if ":" in cidr:
            result["ipv6"].append(cidr)
        else:
            result["ipv4"].append(cidr)
    return result
