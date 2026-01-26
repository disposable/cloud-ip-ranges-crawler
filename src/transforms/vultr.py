from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    result["details_ipv4"] = []
    result["details_ipv6"] = []
    data = response[0].json()

    if isinstance(data, dict):
        subnets = data.get("subnets", [])
        for subnet in subnets:
            ip_prefix = subnet.get("ip_prefix")
            if ip_prefix:
                if ":" in ip_prefix:
                    result["ipv6"].append(ip_prefix)
                    result["details_ipv6"].append({
                        "address": ip_prefix,
                        "alpha2code": subnet.get("alpha2code"),
                        "region": subnet.get("region"),
                        "city": subnet.get("city"),
                        "postal_code": subnet.get("postal_code"),
                    })
                else:
                    result["ipv4"].append(ip_prefix)
                    result["details_ipv4"].append({
                        "address": ip_prefix,
                        "alpha2code": subnet.get("alpha2code"),
                        "region": subnet.get("region"),
                        "city": subnet.get("city"),
                        "postal_code": subnet.get("postal_code"),
                    })

    return result
