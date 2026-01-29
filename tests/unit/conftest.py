import json
from pathlib import Path
from typing import Any

import pytest

from src.cloud_ip_ranges import CloudIPRanges


SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


class FakeResponse:
    """Minimal stand-in for requests.Response for tests.

    Supports .text, .json(), .content, and .raise_for_status().
    """

    def __init__(
        self, *, text: str | None = None, json_data: Any | None = None, content: bytes | None = None, status_code: int = 200, url: str | None = None
    ) -> None:
        self._text = text
        self._json = json_data
        self._content = content
        self.status_code = status_code
        self.headers = {}
        self.url = url

    @property
    def text(self) -> str:
        if self._text is not None:
            return self._text
        if self._json is not None:
            return json.dumps(self._json)
        if self._content is not None:
            try:
                return self._content.decode("utf-8")
            except Exception:
                return ""
        return ""

    def json(self) -> Any:
        if self._json is not None:
            return self._json
        if self._text is not None:
            return json.loads(self._text)
        return json.loads(self.content.decode("utf-8"))

    @property
    def content(self) -> bytes:
        if self._content is not None:
            return self._content
        if self._text is not None:
            return self._text.encode("utf-8")
        if self._json is not None:
            return json.dumps(self._json).encode("utf-8")
        return b""

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


@pytest.fixture
def cipr() -> CloudIPRanges:
    return CloudIPRanges({"json"})


def _load_raw(path: Path) -> FakeResponse:
    return FakeResponse(text=path.read_text(encoding="utf-8"))


def _has_valid_ipv4(result: dict[str, Any]) -> bool:
    import ipaddress

    return any(ipaddress.ip_network(ip, strict=False).version == 4 for ip in result.get("ipv4", []))


def _has_valid_ipv6(result: dict[str, Any]) -> bool:
    import ipaddress

    return any(ipaddress.ip_network(ip, strict=False).version == 6 for ip in result.get("ipv6", []))
