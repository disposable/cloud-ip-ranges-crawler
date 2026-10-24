from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform Mullvad relay list into VPN exit IP ranges."""
    result = cipr._transform_base(source_key)
    result["coverage_notes"] = "Mullvad VPN relay exit IPs (active relays only)"

    for r in response:
        for relay in r.json():
            if not relay.get("active"):
                continue
            ip4 = relay.get("ipv4_addr_in")
            ip6 = relay.get("ipv6_addr_in")
            if ip4:
                result["ipv4"].append(ip4)
            if ip6:
                result["ipv6"].append(ip6)

    return result
