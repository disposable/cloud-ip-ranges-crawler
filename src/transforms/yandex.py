import ipaddress
import re
from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform Yandex corporate IP ranges page."""
    result = cipr._transform_base(source_key)
    text = response[0].text

    seen: set[str] = set()
    for m in re.finditer(r"[0-9a-fA-F:.]+/[0-9]{1,3}", text):
        raw = m.group()
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue

        ip_str = str(network)
        if ip_str in seen:
            continue
        seen.add(ip_str)

        if isinstance(network, ipaddress.IPv4Network):
            result["ipv4"].append(ip_str)
        elif isinstance(network, ipaddress.IPv6Network):
            result["ipv6"].append(ip_str)

    if not result["ipv4"] and not result["ipv6"]:
        raise ValueError("Failed to parse Yandex IP ranges response")

    return result
