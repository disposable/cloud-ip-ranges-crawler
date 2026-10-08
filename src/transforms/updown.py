from typing import Any, Dict, List

from .common import transform_json_ip_list


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    return transform_json_ip_list(cipr, response, source_key)
