from typing import Any, Dict, List

from transforms.common import validate_ip


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform Cloudflare local-ip-ranges.csv (WARP egress IPs) into IP ranges.

    The CSV rows are: cidr,country,subdivision,city - we only need the CIDR.
    """
    result = cipr._transform_base(source_key)
    result["coverage_notes"] = "Cloudflare WARP egress IPs (local-ip-ranges)"

    for r in response:
        for line in (r.text or "").splitlines():
            prefix = line.split(",", 1)[0].strip()
            if not prefix or not validate_ip(prefix):
                continue
            if ":" in prefix:
                result["ipv6"].append(prefix)
            else:
                result["ipv4"].append(prefix)

    return result
