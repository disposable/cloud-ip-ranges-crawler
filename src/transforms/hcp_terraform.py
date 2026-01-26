from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    data = response[0].json()

    # Expected shape: {"api": [...], "notifications": [...], "sentinel": [...], "vcs": [...]}.
    if not isinstance(data, dict):
        return result

    for key in ("api", "notifications", "sentinel", "vcs"):
        values = data.get(key)
        if not isinstance(values, list):
            continue
        for cidr in values:
            if not isinstance(cidr, str):
                continue
            if ":" in cidr:
                result["ipv6"].append(cidr)
            else:
                result["ipv4"].append(cidr)

    return result
