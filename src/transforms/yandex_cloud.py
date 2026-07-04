import ipaddress
import re
from typing import Any, Dict, List

# Sections on the page that contain IP ranges (Cloud CDN is a link, not inline)
_SECTIONS: Dict[str, str] = {
    "Virtual Private Cloud": "Virtual Private Cloud",
    "BareMetal": "BareMetal",
    "SmartCaptcha": "SmartCaptcha",
    "Smart Web Security": "Smart Web Security",
    "DSPM": "DSPM",
    "IP addresses used by Yandex Cloud for its services": "Yandex Cloud Services",
}


# Match bare IPv4 or IPv4 CIDR
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")
# Match IPv6 or IPv6 CIDR (must contain :: or at least one colon group)
_IPV6_RE = re.compile(r"\b[0-9a-fA-F:]{4,}(?:/[0-9]{1,3})?\b")


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform Yandex Cloud HTML documentation page to extract CIDR ranges."""
    result = cipr._transform_base(source_key)

    text = response[0].text
    current_section: str | None = None

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        # Detect section heading
        for heading, service in _SECTIONS.items():
            if line == heading or line.startswith(heading):
                current_section = service
                break

        if current_section is None:
            continue

        # Skip metadata / helper lines that are not IPs
        if line in ("IPv4", "IPv6"):
            continue

        candidates: List[str] = []
        candidates.extend(_IPV4_RE.findall(line))
        candidates.extend(_IPV6_RE.findall(line))

        for raw in candidates:
            try:
                network = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                continue

            ip_str = str(network)
            if isinstance(network, ipaddress.IPv4Network):
                result["ipv4"].append(ip_str)
                result.setdefault("details_ipv4", []).append({"address": ip_str, "service": current_section})
            elif isinstance(network, ipaddress.IPv6Network):
                result["ipv6"].append(ip_str)
                result.setdefault("details_ipv6", []).append({"address": ip_str, "service": current_section})

    if not result["ipv4"] and not result["ipv6"]:
        raise ValueError("Failed to parse Yandex Cloud HTML response")

    return result
