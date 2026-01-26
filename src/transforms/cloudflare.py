from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)

    data = [r.text for r in response]

    if isinstance(data[0], str):
        result["ipv4"] = data[0].splitlines()

    if isinstance(data[1], str):
        result["ipv6"] = data[1].splitlines()

    return result
