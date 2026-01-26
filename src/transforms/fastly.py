from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    data = response[0].json()

    if isinstance(data, dict):
        for ip in data.get("addresses", []):
            result["ipv4"].append(ip)

        for ip in data.get("ipv6_addresses", []):
            result["ipv6"].append(ip)

    return result
