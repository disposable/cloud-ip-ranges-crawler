import json
from typing import Any, Dict, List

# Server groups that carry VPN user traffic. "meta" entries are API/management
# endpoints, not exit relays, so they are excluded.
VPN_SERVER_GROUPS = ("wg", "ovpnudp", "ovpntcp", "ikev2")


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform Private Internet Access server list into VPN exit IP ranges.

    The /vpninfo/servers/v6 payload is a single JSON line followed by a
    signature block; only the first line is parsed.
    """
    result = cipr._transform_base(source_key)
    result["coverage_notes"] = "Private Internet Access VPN server exit IPs"

    for r in response:
        first_line = (r.text or "").splitlines()[0]
        data = json.loads(first_line)
        for region in data.get("regions", []):
            if region.get("offline"):
                continue
            servers = region.get("servers", {})
            for group in VPN_SERVER_GROUPS:
                for server in servers.get(group, []):
                    ip = server.get("ip")
                    if ip:
                        result["ipv4"].append(ip)

    return result
