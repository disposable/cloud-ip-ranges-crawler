from typing import Any, Dict, List

from .common import transform_google_style


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    return transform_google_style(cipr, response, source_key)
