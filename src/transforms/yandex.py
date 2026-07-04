import ipaddress
from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform Yandex corporate IP ranges page."""
    result = cipr._transform_base(source_key)
    text = response[0].text

    current_section: str | None = None

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        if line == "IP v4":
            current_section = "ipv4"
            continue
        if line == "IP v6":
            current_section = "ipv6"
            continue

        if current_section is None:
            continue

        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue

        ip_str = str(network)
        if isinstance(network, ipaddress.IPv4Network):
            result["ipv4"].append(ip_str)
        elif isinstance(network, ipaddress.IPv6Network):
            result["ipv6"].append(ip_str)

    if not result["ipv4"] and not result["ipv6"]:
        raise ValueError("Failed to parse Yandex IP ranges response")

    return result
