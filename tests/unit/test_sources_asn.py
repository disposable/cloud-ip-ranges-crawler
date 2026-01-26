"""Unit tests for src.sources.asn helper functions."""

from __future__ import annotations

import pytest

from src.sources import asn


def setup_function(function):
    """Clear the RADB whois cache before each test to avoid cross-test bleed."""
    asn.radb_whois_query.cache_clear()


class _DummySocket:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self._chunks = [b"foo", b"bar", b""]

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, _: int) -> bytes:
        return self._chunks.pop(0)

    def __enter__(self) -> "_DummySocket":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # pragma: no cover - nothing to clean up
        return None


def test_radb_whois_query_requires_non_empty_input() -> None:
    with pytest.raises(ValueError):
        asn.radb_whois_query("   ")


def test_radb_whois_query_reads_all_socket_chunks(monkeypatch: pytest.MonkeyPatch) -> None:
    dummy = _DummySocket()

    def fake_create_connection(addr, timeout):
        assert addr == (asn._RADB_HOST, asn._RADB_PORT)
        assert timeout == 10
        return dummy

    monkeypatch.setattr(asn.socket, "create_connection", fake_create_connection)

    result = asn.radb_whois_query("AS-TEST")
    assert result == "foobar"
    assert dummy.sent == [b"AS-TEST\r\n"]


def test__radb_extract_members_handles_continuations_and_mixed_cases() -> None:
    whois = (
        "members: AS123, as456, AS-FOO\n"
        "  AS789 RS-BAR\n"
        "mp-members: rs-extra\n"
        "\n"
        "members:   AS999\n"
        "other: ignored\n"
    )
    members = asn._radb_extract_members(whois)
    assert members == [
        "AS123",
        "as456",
        "AS-FOO",
        "AS789",
        "RS-BAR",
        "rs-extra",
        "AS999",
    ]


def test_radb_resolve_as_set_recurses_and_deduplicates(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    responses = {
        "AS-ROOT": "members: as111 AS-CHILD RS-EXTRA\n",
        "AS-CHILD": "members: AS222 AS-LOOP\n",
        "RS-EXTRA": "members: AS333\n",
        "AS-LOOP": "members: AS111 AS-ROOT\n",
    }

    def fake_query(name: str) -> str:
        calls.append(name)
        return responses[name]

    monkeypatch.setattr(asn, "radb_whois_query", fake_query)

    result = asn.radb_resolve_as_set("as-root", max_depth=5)
    assert result == {"AS111", "AS222", "AS333"}
    assert calls.count("AS-CHILD") == 1  # ensure we don't revisit already-seen sets


def test_radb_resolve_as_set_respects_max_depth(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_query(name: str) -> str:
        if name == "AS-FOO":
            return "members: AS100 AS-CHILD\n"
        pytest.fail("Child set should not be queried when depth limit is 0")

    monkeypatch.setattr(asn, "radb_whois_query", fake_query)

    result = asn.radb_resolve_as_set("AS-FOO", max_depth=0)
    assert result == {"AS100"}
