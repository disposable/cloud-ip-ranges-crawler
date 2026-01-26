from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    data = response[0].json()

    # Expected shape: {"Location name": ["CIDR", ...], ...}
    if not isinstance(data, dict):
        return result

    for _, cidrs in data.items():
        if not isinstance(cidrs, list):
            continue
        for cidr in cidrs:
            if not isinstance(cidr, str):
                continue
            if ":" in cidr:
                result["ipv6"].append(cidr)
            else:
                result["ipv4"].append(cidr)

    return result
