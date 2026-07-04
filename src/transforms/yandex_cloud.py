import ipaddress
import re
from typing import Any, Dict, List, Tuple

# Sections on the page that contain IP ranges (Cloud CDN is a link, not inline)
_SECTIONS: Dict[str, str] = {
    "Virtual Private Cloud": "Virtual Private Cloud",
    "BareMetal": "BareMetal",
    "SmartCaptcha": "SmartCaptcha",
    "Smart Web Security": "Smart Web Security",
    "DSPM": "DSPM",
    "IP addresses used by Yandex Cloud for its services": "Yandex Cloud Services",
}


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform Yandex Cloud HTML documentation page to extract CIDR ranges."""
    result = cipr._transform_base(source_key)
    text = response[0].text

    # Find all section heading positions (works with both rendered text and HTML)
    section_positions: List[Tuple[int, str]] = []
    for heading, service in _SECTIONS.items():
        for m in re.finditer(re.escape(heading), text):
            section_positions.append((m.start(), service))
    section_positions.sort()

    # Extract all CIDRs and bare IPs with their positions
    cidr_items: List[Tuple[int, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for m in re.finditer(r"[0-9a-fA-F:.]+(?:/[0-9]{1,3})?", text):
        raw = m.group()
        try:
            if "/" in raw:
                network = ipaddress.ip_network(raw, strict=False)
            else:
                addr = ipaddress.ip_address(raw)
                prefix = "32" if isinstance(addr, ipaddress.IPv4Address) else "128"
                network = ipaddress.ip_network(f"{raw}/{prefix}", strict=False)
            cidr_items.append((m.start(), network))
        except ValueError:
            continue

    # Assign each CIDR to the nearest preceding section
    for pos, network in cidr_items:
        section: str | None = None
        for sec_pos, sec_name in section_positions:
            if sec_pos < pos:
                section = sec_name
            else:
                break

        ip_str = str(network)
        if isinstance(network, ipaddress.IPv4Network):
            result["ipv4"].append(ip_str)
            if section:
                result.setdefault("details_ipv4", []).append({"address": ip_str, "service": section})
        elif isinstance(network, ipaddress.IPv6Network):
            result["ipv6"].append(ip_str)
            if section:
                result.setdefault("details_ipv6", []).append({"address": ip_str, "service": section})

    if not result["ipv4"] and not result["ipv6"]:
        raise ValueError("Failed to parse Yandex Cloud HTML response")

    return result
