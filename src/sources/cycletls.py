"""HTTP source handling using cycletls for sources that block plain requests."""

import logging
import time
from typing import Any, Dict, List

from cycletls import CycleTLS, ConnectionError, Timeout
from transforms.registry import get_transform

_TIMEOUT_SECONDS = 30
_MAX_RETRIES = 3
_BACKOFF_BASE = 1.0


def _fetch_with_retry(client: CycleTLS, url: str, source_key: str, max_retries: int = _MAX_RETRIES) -> Any:
    """Fetch a single URL with retries on transient network/timeout errors."""
    last_exception: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            return client.get(url, timeout=_TIMEOUT_SECONDS)
        except (ConnectionError, Timeout) as e:
            last_exception = e
            logging.warning(
                "Attempt %d/%d failed for %s (%s): %s",
                attempt,
                max_retries,
                source_key,
                url,
                str(e),
            )
            if attempt < max_retries:
                time.sleep(_BACKOFF_BASE * (2 ** (attempt - 1)))
    raise last_exception  # type: ignore[reportGeneralTypeIssues]


def fetch_and_save_cycletls_source(cipr: Any, source_key: str, url: List[str]) -> Dict[str, Any]:
    """Fetch and save HTTP-based source using cycletls to bypass detection."""
    source_http: List[Dict[str, Any]] = []
    response: List[Any] = []

    client = CycleTLS()
    try:
        for u in url:
            try:
                resp = _fetch_with_retry(client, u, source_key)
                status = getattr(resp, "status_code", 0) or 0
                if status >= 400:
                    raise RuntimeError(f"{source_key}: {u} returned HTTP {status}")
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
