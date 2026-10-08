from typing import Any, Dict, List

from .common import transform_csv_format


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    return transform_csv_format(cipr, response, source_key)
