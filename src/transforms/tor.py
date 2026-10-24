from typing import Any, Dict, List

from .common import transform_csv_format


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = transform_csv_format(cipr, response, source_key)
    result["coverage_notes"] = "Tor exit node IPs (bulk exit list)"
    return result
