from typing import Any, Dict, List

from .seed_rdap_registry import transform as seed_rdap_registry_transform


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = seed_rdap_registry_transform(cipr, response, source_key)
    result["coverage_notes"] = "Vercel-owned netblocks (registry), not the full set of cloud egress/edge IPs"
    return result
