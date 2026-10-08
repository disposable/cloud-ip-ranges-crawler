import re
from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    # The Travis CI docs page lists its NAT IP addresses inside <code> elements
    result = cipr._transform_base(source_key)

    for r in response:
        for match in re.findall(r"<code[^>]*>([^<]+)</code>", r.text):
            ip = match.strip()
            if not ip:
                continue
            if ":" in ip:
                result["ipv6"].append(ip)
            else:
                result["ipv4"].append(ip)

    return result
