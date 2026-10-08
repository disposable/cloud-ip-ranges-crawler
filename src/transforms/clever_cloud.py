from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    result["details_ipv4"] = []
    result["details_ipv6"] = []

    data = response[0].json()
    if not isinstance(data, list):
        return result

    for zone in data:
        if not isinstance(zone, dict):
            continue
        zone_name = zone.get("name")
        for ip in zone.get("outboundIPs") or []:
            if not isinstance(ip, str):
                continue
            if ":" in ip:
                result["ipv6"].append(ip)
                result["details_ipv6"].append({"address": ip, "scope": zone_name})
            else:
                result["ipv4"].append(ip)
                result["details_ipv4"].append({"address": ip, "scope": zone_name})

    return result
