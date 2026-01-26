import re
from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    result["details_ipv4"] = []
    result["details_ipv6"] = []

    match = re.findall(r"<a href=\"([^\"]+)\"", response[0].text)
    downloads: List[Any] = []
    for u in match:
        if not u.startswith("https://download.microsoft.com/"):
            continue

        r = cipr.session.get(u, timeout=10)
        r.raise_for_status()
        downloads.append(r)

    ipv4 = set()
    ipv6 = set()
    details_ipv4 = []
    details_ipv6 = []

    for r in downloads:
        data = r.json()
        values = data.get("values", [])
        for value in values:
            properties = value.get("properties", {})
            system_service = properties.get("systemService")
            region = properties.get("region")
            addresses = properties.get("addressPrefixes", [])
            for address in addresses:
                if ":" in address:
                    ipv6.add(address)
                    details_ipv6.append({"address": address, "systemService": system_service, "region": region})
                else:
                    ipv4.add(address)
                    details_ipv4.append({"address": address, "systemService": system_service, "region": region})

    result["ipv4"] = list(ipv4)
    result["ipv6"] = list(ipv6)
    if details_ipv4:
        result["details_ipv4"] = details_ipv4
    if details_ipv6:
        result["details_ipv6"] = details_ipv6
    return result
