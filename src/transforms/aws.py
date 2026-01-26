from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    result["details_ipv4"] = []
    result["details_ipv6"] = []
    data = response[0].json()
    result["last_update"] = data["createDate"]
    result["source_updated_at"] = data["createDate"]

    if "prefixes" in data:
        for prefix in data["prefixes"]:
            ip = prefix.get("ip_prefix")
            if not ip:
                continue
            result["ipv4"].append(ip)
            result["details_ipv4"].append({
                "address": ip,
                "service": prefix.get("service"),
                "region": prefix.get("region"),
                "network_border_group": prefix.get("network_border_group"),
            })

    if "ipv6_prefixes" in data:
        for prefix in data["ipv6_prefixes"]:
            ip6 = prefix.get("ipv6_prefix")
            if not ip6:
                continue
            result["ipv6"].append(ip6)
            result["details_ipv6"].append({
                "address": ip6,
                "service": prefix.get("service"),
                "region": prefix.get("region"),
                "network_border_group": prefix.get("network_border_group"),
            })

    return result
