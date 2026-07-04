from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    result["provider"] = "Bunny CDN"

    for r in response:
        text = r.text or ""
        for line in text.splitlines():
            ip = line.strip().replace("\r", "")
            if not ip:
                continue
            if ":" in ip:
                result["ipv6"].append(ip)
            else:
                result["ipv4"].append(ip)

    return result
