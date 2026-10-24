from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform NordVPN server list into VPN exit IP ranges."""
    result = cipr._transform_base(source_key)
    result["coverage_notes"] = "NordVPN server exit IPs (online servers only)"

    for r in response:
        for server in r.json():
            if server.get("status") != "online":
                continue
            ip4 = server.get("station")
            ip6 = server.get("ipv6_station")
            if ip4:
                result["ipv4"].append(ip4)
            if ip6:
                result["ipv6"].append(ip6)

    return result
