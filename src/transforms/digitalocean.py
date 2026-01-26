from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    data = response[0].text

    lines = data.splitlines()
    for line in lines:
        if not line.strip():
            continue
        prefix = line.split(",")[0]
        if ":" in prefix:
            result["ipv6"].append(prefix)
        else:
            result["ipv4"].append(prefix)

    return result
