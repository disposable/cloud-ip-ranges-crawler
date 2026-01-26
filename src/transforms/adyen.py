import re
import socket
from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)

    # Extract static CIDR ranges from Adyen docs page
    text = response[0].text
    cidrs = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", text)

    for cidr in cidrs:
        result["ipv4"].append(cidr)

    # Also resolve out.adyen.com via DNS as recommended in Adyen docs
    try:
        # Resolve out.adyen.com to IP addresses
        ips = socket.gethostbyname_ex("out.adyen.com")[2]
        for ip in ips:
            # Normalize bare IPs to /32 CIDR notation
            result["ipv4"].append(f"{ip}/32")
    except (socket.gaierror, socket.herror, OSError):
        # DNS resolution failed - continue with static CIDRs only
        pass

    return result
