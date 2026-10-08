from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)

    for r in response:
        data = r.json()
        if not isinstance(data, dict):
            continue
        for ip in data.get("ipRanges") or []:
            if isinstance(ip, str):
                result["ipv4"].append(ip)
        for ip in data.get("ipv6Ranges") or []:
            if isinstance(ip, str):
                result["ipv6"].append(ip)

    return result
