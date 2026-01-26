from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    data = response[0].json()

    # Expected shape:
    # {"IPRanges": {"macOS": ["..."] , "jobs": ["..."] , "core": ["..."]}}
    ip_ranges = data.get("IPRanges") if isinstance(data, dict) else None
    if not isinstance(ip_ranges, dict):
        return result

    for _, values in ip_ranges.items():
        if not isinstance(values, list):
            continue
        for ip in values:
            if not isinstance(ip, str):
                continue
            # CircleCI mixes bare IPs and CIDR ranges; normalize to /32 and /128.
            if "/" not in ip:
                ip = f"{ip}/128" if ":" in ip else f"{ip}/32"
            if ":" in ip:
                result["ipv6"].append(ip)
            else:
                result["ipv4"].append(ip)

    return result
