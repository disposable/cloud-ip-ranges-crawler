from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)

    # Each endpoint returns a JSON array of IP addresses (no CIDR). Normalize to /32 and /128.
    for r in response:
        data = r.json()
        if not isinstance(data, list):
            continue
        for ip in data:
            if not isinstance(ip, str):
                continue
            if "/" not in ip:
                ip = f"{ip}/128" if ":" in ip else f"{ip}/32"
            if ":" in ip:
                result["ipv6"].append(ip)
            else:
                result["ipv4"].append(ip)

    return result
