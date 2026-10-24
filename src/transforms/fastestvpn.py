from typing import Any, Dict, List

from .common import transform_gluetun_servers


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = transform_gluetun_servers(cipr, response, source_key)
    result["coverage_notes"] = "VPN server exit IPs via gluetun-servers mirror"
    return result
