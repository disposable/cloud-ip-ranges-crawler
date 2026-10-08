import re
from typing import Any, Dict, List

_CIDR = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b|\b[0-9a-fA-F:]+:[0-9a-fA-F:]*/[0-9]{1,3}\b")


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    # Sucuri documents its firewall CIDRs inline in the troubleshooting guide
    result = cipr._transform_base(source_key)

    for r in response:
        for cidr in _CIDR.findall(r.text):
            if ":" in cidr:
                result["ipv6"].append(cidr)
            else:
                result["ipv4"].append(cidr)

    return result
