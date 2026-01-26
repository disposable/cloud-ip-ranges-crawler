from typing import Any, Dict, List

from .common import transform_csv_format


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = transform_csv_format(cipr, response, source_key)
    # Add coverage notes to clarify this is user ISP traffic, not crawler traffic
    result["coverage_notes"] = "User ISP traffic from Starlink satellite internet service. These are regular user connections, not crawler or bot traffic."
    return result
