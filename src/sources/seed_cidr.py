"""Seed CIDR source handling for providers like Vercel."""

import logging
from typing import Any, Dict, List

from transforms.registry import get_transform


def fetch_and_save_seed_cidr_source(cipr: Any, source_key: str, seeds: List[str]) -> Dict[str, Any]:
    """Fetch and save seed CIDR-based source."""
    source_http: List[Dict[str, Any]] = []
    response: List[Any] = []

    for seed in seeds:
        rdap_url = f"https://rdap.arin.net/registry/ip/{seed.split('/')[0]}"
        try:
            r = cipr.session.get(rdap_url, timeout=10)
            r.raise_for_status()
            response.append(r)
            source_http.append({
                "url": rdap_url,
                "status": r.status_code,
                "content_type": r.headers.get("content-type"),
                "etag": r.headers.get("etag"),
                "last_modified": r.headers.get("last-modified"),
            })
        except Exception as e:
            logging.error("Failed to fetch RDAP for %s seed %s: %s", source_key, seed, str(e))
            raise RuntimeError(f"Failed to fetch RDAP for {source_key}") from e

    transform_fn = get_transform(source_key)
    transformed_data = transform_fn(cipr, response, source_key)
    transformed_data = cipr._normalize_transformed_data(transformed_data, source_key)
    transformed_data["source_http"] = source_http

    return transformed_data
