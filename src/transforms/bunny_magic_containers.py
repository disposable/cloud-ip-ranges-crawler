import json
from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    result["provider"] = "Bunny Magic Containers"
    text = response[0].text or ""

    # The API may return a JSON array or a plain text list
    try:
        ips = json.loads(text)
        if not isinstance(ips, list):
            ips = []
    except (json.JSONDecodeError, ValueError):
        ips = text.splitlines()

    for ip in ips:
        ip = ip.strip()
        if not ip:
            continue
        if ":" in ip:
            result["ipv6"].append(f"{ip}/128")
        else:
            result["ipv4"].append(f"{ip}/32")

    return result
