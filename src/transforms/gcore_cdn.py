from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    result["provider"] = "Gcore CDN"
    data = response[0].json()

    if isinstance(data, dict):
        for addr in data.get("addresses", []):
            if not addr:
                continue
            if ":" in addr:
                result["ipv6"].append(addr)
            else:
                result["ipv4"].append(addr)

    return result
