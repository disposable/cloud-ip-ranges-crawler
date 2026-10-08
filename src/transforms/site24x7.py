from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    # The download link on the Site24x7 monitoring-locations page points to a
    # Zoho Creator JSON view: {"IP_Address_View": [{"external_ip": ..., "IPv6_Address_External": ...}]}
    result = cipr._transform_base(source_key)
    result["details_ipv4"] = []
    result["details_ipv6"] = []

    for r in response:
        data = r.json()
        if not isinstance(data, dict):
            continue
        locations = data.get("IP_Address_View")
        if not isinstance(locations, list):
            continue
        for loc in locations:
            if not isinstance(loc, dict):
                continue
            scope = loc.get("Place") or loc.get("City")
            ipv4 = loc.get("external_ip")
            if isinstance(ipv4, str) and ipv4.strip():
                result["ipv4"].append(ipv4.strip())
                result["details_ipv4"].append({"address": ipv4.strip(), "scope": scope})
            ipv6 = loc.get("IPv6_Address_External")
            if isinstance(ipv6, str) and ipv6.strip():
                result["ipv6"].append(ipv6.strip())
                result["details_ipv6"].append({"address": ipv6.strip(), "scope": scope})

    return result
