from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform IVPN server list into VPN exit IP ranges."""
    result = cipr._transform_base(source_key)
    result["coverage_notes"] = "IVPN server exit IPs"

    for r in response:
        data = r.json()
        for proto in ("wireguard", "openvpn"):
            for gateway in data.get(proto, []):
                for host in gateway.get("hosts", []):
                    ip = host.get("host")
                    if ip:
                        result["ipv4"].append(ip)

    return result
