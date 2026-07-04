"""HTTP source handling using cycletls for sources that block plain requests."""

import logging
from typing import Any, Dict, List

from cycletls import CycleTLS
from transforms.registry import get_transform


def fetch_and_save_cycletls_source(cipr: Any, source_key: str, url: List[str]) -> Dict[str, Any]:
    """Fetch and save HTTP-based source using cycletls to bypass detection."""
    source_http: List[Dict[str, Any]] = []
    response: List[Any] = []

    client = CycleTLS()
    try:
        for u in url:
            try:
                resp = client.get(u)
                response.append(resp)
                source_http.append({
                    "url": u,
                    "status": resp.status_code,
                    "content_type": resp.headers.get("content-type"),
                    "etag": resp.headers.get("etag"),
                    "last_modified": resp.headers.get("last-modified"),
                })
            except Exception as e:
                logging.error("Failed to fetch %s for %s via cycletls: %s", u, source_key, str(e))
                raise RuntimeError(f"Failed to fetch {source_key}") from e
    finally:
        client.close()

    transform_fn = get_transform(source_key)
    transformed_data = transform_fn(cipr, response, source_key)
    transformed_data = cipr._normalize_transformed_data(transformed_data, source_key)
    transformed_data["source_http"] = source_http

    return transformed_data
