from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    result["details_ipv4"] = []
    result["details_ipv6"] = []
    data = response[0].json()

    if isinstance(data, dict):
        regions = data.get("regions", [])
        for region in regions:
            cidrs = region.get("cidrs", [])
            ipv4_cidrs = region.get("ipv4_cidrs", [])
            ipv6_cidrs = region.get("ipv6_cidrs", [])

            for cidr in cidrs:
                ip = cidr.get("cidr")
                if ip:
                    if ":" in ip:
                        result["ipv6"].append(ip)
                        result["details_ipv6"].append({"address": ip, "region": region.get("region") or region.get("regionKey")})
                    else:
                        result["ipv4"].append(ip)
                        result["details_ipv4"].append({"address": ip, "region": region.get("region") or region.get("regionKey")})

            for cidr in ipv4_cidrs:
                ip = cidr.get("cidr")
                if ip:
                    result["ipv4"].append(ip)
                    result["details_ipv4"].append({"address": ip, "region": region.get("region") or region.get("regionKey")})

            for cidr in ipv6_cidrs:
                ip = cidr.get("cidr")
                if ip:
                    result["ipv6"].append(ip)
                    result["details_ipv6"].append({"address": ip, "region": region.get("region") or region.get("regionKey")})

    return result
