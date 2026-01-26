"""HTTP source handling for regular API/URL sources."""

import logging
from typing import Any, Dict, List

from transforms.registry import get_transform


def fetch_and_save_http_source(cipr: Any, source_key: str, url: List[str]) -> Dict[str, Any]:
    """Fetch and save HTTP-based source."""
    source_http: List[Dict[str, Any]] = []
    response: List[Any] = []

    for u in url:
        try:
            r = cipr.session.get(u, timeout=10)
            r.raise_for_status()
            response.append(r)
            source_http.append({
                "url": u,
                "status": r.status_code,
                "content_type": r.headers.get("content-type"),
                "etag": r.headers.get("etag"),
                "last_modified": r.headers.get("last-modified"),
            })
        except Exception as e:
            logging.error("Failed to fetch %s for %s: %s", u, source_key, str(e))
            raise RuntimeError(f"Failed to fetch {source_key}") from e

    transform_fn = get_transform(source_key)
    transformed_data = transform_fn(cipr, response, source_key)
    transformed_data = cipr._normalize_transformed_data(transformed_data, source_key)
    transformed_data["source_http"] = source_http

    return transformed_data
