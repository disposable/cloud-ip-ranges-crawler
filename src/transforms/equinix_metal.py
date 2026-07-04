from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    result["provider"] = "Equinix Metal"
    data = response[0].text or ""

    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(",")
        if not parts:
            continue

        cidr = parts[0].strip()
        if not cidr:
            continue

        if ":" in cidr:
            result["ipv6"].append(cidr)
        else:
            result["ipv4"].append(cidr)

    return result
