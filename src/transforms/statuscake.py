from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    result["details_ipv4"] = []
    result["details_ipv6"] = []

    for r in response:
        data = r.json()
        if isinstance(data, dict):
            probes = data.values()
        elif isinstance(data, list):
            probes = data
        else:
            continue
        for probe in probes:
            if not isinstance(probe, dict):
                continue
            location = probe.get("title")
            ipv4 = probe.get("ip")
            if isinstance(ipv4, str) and ipv4:
                result["ipv4"].append(ipv4)
                result["details_ipv4"].append({"address": ipv4, "scope": location})
            ipv6 = probe.get("ipv6")
            if isinstance(ipv6, str) and ipv6:
                result["ipv6"].append(ipv6)
                result["details_ipv6"].append({"address": ipv6, "scope": location})

    return result
