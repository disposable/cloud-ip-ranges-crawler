import re
from typing import Any, Dict, List

# quic.cloud/ips serves a bare IP list separated by <br /> tags.
_LINE_SPLIT = re.compile(r"<br\s*/?>|\r?\n")
_TAG = re.compile(r"<[^>]+>")


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)

    for r in response:
        for line in _LINE_SPLIT.split(r.text):
            ip = _TAG.sub("", line).strip()
            if not ip:
                continue
            if ":" in ip:
                result["ipv6"].append(ip)
            else:
                result["ipv4"].append(ip)

    return result
