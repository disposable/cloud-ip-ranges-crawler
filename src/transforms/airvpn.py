from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform AirVPN status endpoint into VPN exit IP ranges."""
    result = cipr._transform_base(source_key)
    result["coverage_notes"] = "AirVPN server exit IPs"

    for r in response:
        data = r.json()
        for server in data.get("servers", []):
            for i in range(1, 5):
                ip4 = server.get(f"ip_v4_in{i}")
                ip6 = server.get(f"ip_v6_in{i}")
                if ip4:
                    result["ipv4"].append(ip4)
                if ip6:
                    result["ipv6"].append(ip6)

    return result
