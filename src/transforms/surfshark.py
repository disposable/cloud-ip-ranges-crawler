import logging
import socket
from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform Surfshark cluster list into VPN exit IP ranges.

    The API only publishes a load-balanced connectionName per cluster, so
    hostnames are resolved via DNS. One query returns a subset of the
    cluster's egress IPs; coverage grows as runs accumulate.
    """
    result = cipr._transform_base(source_key)
    result["coverage_notes"] = "Surfshark VPN exit IPs (DNS-resolved cluster endpoints)"

    hostnames: set[str] = set()
    for r in response:
        for cluster in r.json():
            name = cluster.get("connectionName")
            if name:
                hostnames.add(name)

    for hostname in sorted(hostnames):
        try:
            infos = socket.getaddrinfo(hostname, None)
        except OSError as e:
            logging.warning("Failed to resolve %s: %s", hostname, e)
            continue
        for info in infos:
            ip = info[4][0]
            if ":" in ip:
                result["ipv6"].append(ip)
            else:
                result["ipv4"].append(ip)

    return result
