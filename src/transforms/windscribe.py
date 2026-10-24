from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform Windscribe server list into VPN exit IP ranges.

    Each node exposes ip, ip2 and ip3 - the server's addresses across
    protocols; all are VPN infrastructure IPs.
    """
    result = cipr._transform_base(source_key)
    result["coverage_notes"] = "Windscribe VPN server IPs"

    for r in response:
        data = r.json()
        for location in data.get("data", []):
            for group in location.get("groups", []):
                for node in group.get("nodes", []):
                    for key in ("ip", "ip2", "ip3"):
                        ip = node.get(key)
                        if ip:
                            result["ipv4"].append(ip)

    return result
