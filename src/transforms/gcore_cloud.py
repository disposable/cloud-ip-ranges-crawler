from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    result["provider"] = "Gcore Cloud"
    data = response[0].json()

    if isinstance(data, dict):
        for ip_range in data.get("ranges", []):
            if not ip_range:
                continue
            if ":" in ip_range:
                result["ipv6"].append(ip_range)
            else:
                result["ipv4"].append(ip_range)

    return result
