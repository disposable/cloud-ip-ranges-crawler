from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List, Optional


def validate_ip(ip: str) -> Optional[str]:
    """Validate an IP address or subnet."""
    try:
        network = ipaddress.ip_network(ip, strict=False)

        if network.is_private or network.is_loopback or network.is_link_local or network.is_multicast:
            return None

        return str(network)
    except ValueError as e:
        logging.warning("Invalid IP address/subnet: %s - %s", ip, str(e))
        return None


def transform_csv_format(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    data = response[0].text

    lines = data.splitlines()
    for line in lines:
        if not line.strip() or line.startswith("#"):
            continue

        ip = line.split(",")[0]
        if ":" in ip:
            result["ipv6"].append(ip)
        else:
            result["ipv4"].append(ip)

    return result


def transform_google_style(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    result["details_ipv4"] = []
    result["details_ipv6"] = []

    for r in response:
        data = r.json()
        result["last_update"] = data["creationTime"]
        result["source_updated_at"] = data["creationTime"]

        prefixes = data.get("prefixes", [])
        for prefix in prefixes:
            if "ipv4Prefix" in prefix:
                ip = prefix["ipv4Prefix"]
                result["ipv4"].append(ip)
                result["details_ipv4"].append({
                    "address": ip,
                    "service": prefix.get("service"),
                    "scope": prefix.get("scope"),
                })
            if "ipv6Prefix" in prefix:
                ip6 = prefix["ipv6Prefix"]
                result["ipv6"].append(ip6)
                result["details_ipv6"].append({
                    "address": ip6,
                    "service": prefix.get("service"),
                    "scope": prefix.get("scope"),
                })

    return result
