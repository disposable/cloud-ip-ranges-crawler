"""Property-based tests (Hypothesis) for core parsing/merging invariants.

These complement the example-based unit tests by fuzzing the functions that
process untrusted provider data: validate_ip, _comparable_payload,
_extract_cidrs_from_json and IPMerger network collapsing.
"""

from __future__ import annotations

import ipaddress

from hypothesis import HealthCheck, given, settings, strategies as st

from cloud_ip_ranges import CloudIPRanges
from ip_merger import IPMerger
from transforms.common import validate_ip

cidr_v4 = st.tuples(st.ip_addresses(v=4), st.integers(0, 24)).map(lambda t: str(ipaddress.ip_network(f"{t[0]}/{t[1]}", strict=False)))
cidr_v6 = st.tuples(st.ip_addresses(v=6), st.integers(0, 64)).map(lambda t: str(ipaddress.ip_network(f"{t[0]}/{t[1]}", strict=False)))
cidr_any = st.one_of(cidr_v4, cidr_v6)

fast = settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow], deadline=None)


class TestValidateIpProperties:
    @given(st.text())
    @fast
    def test_never_crashes_on_arbitrary_input(self, value: str) -> None:
        result = validate_ip(value)
        assert result is None or ipaddress.ip_network(result, strict=False)

    @given(cidr_any)
    @fast
    def test_public_cidrs_round_trip(self, cidr: str) -> None:
        net = ipaddress.ip_network(cidr)
        if net.is_private or net.is_loopback or net.is_link_local or net.is_multicast:
            return
        result = validate_ip(cidr)
        assert result == str(net)

    @given(st.text())
    @fast
    def test_result_is_canonical(self, value: str) -> None:
        result = validate_ip(value)
        if result is not None:
            assert ipaddress.ip_network(result, strict=False) == ipaddress.ip_network(result, strict=True)


def _payload_strategy() -> st.SearchStrategy[dict]:
    detail = st.fixed_dictionaries({
        "address": cidr_v4,
        "service": st.one_of(st.none(), st.text(max_size=20)),
    })
    retired_detail = st.fixed_dictionaries({
        "address": cidr_v4,
        "service": st.one_of(st.none(), st.text(max_size=20)),
        "retired_at": st.datetimes().map(lambda d: d.isoformat()),
    })
    return st.fixed_dictionaries({
        "provider_id": st.text(min_size=1, max_size=20),
        "ipv4": st.lists(cidr_v4, max_size=10),
        "ipv6": st.lists(cidr_v6, max_size=5),
        "last_update": st.text(max_size=30),
        "generated_at": st.text(max_size=30),
        "source_http": st.lists(st.dictionaries(st.text(max_size=5), st.text(max_size=10), max_size=3), max_size=3),
        "details_ipv4": st.lists(st.one_of(detail, retired_detail), max_size=10),
        "details_ipv6": st.lists(st.one_of(detail, retired_detail), max_size=5),
    })


class TestComparablePayloadProperties:
    @given(_payload_strategy())
    @fast
    def test_volatile_fields_and_retired_stripped(self, payload: dict) -> None:
        cipr = CloudIPRanges({"json"})
        comparable = cipr._comparable_payload(payload)

        for key in ("last_update", "generated_at", "source_http"):
            assert key not in comparable

        retired = {d["address"] for det in (payload.get("details_ipv4") or [], payload.get("details_ipv6") or []) for d in det if "retired_at" in d}
        if retired:
            assert retired.isdisjoint(comparable.get("ipv4", []))
            assert retired.isdisjoint(comparable.get("ipv6", []))

        for key in ("details_ipv4", "details_ipv6"):
            for d in comparable.get(key, []):
                assert "retired_at" not in d

        # Non-retired published CIDRs are preserved
        assert set(payload["ipv4"]) - retired <= set(comparable.get("ipv4", []))

    @given(_payload_strategy())
    @fast
    def test_idempotent(self, payload: dict) -> None:
        cipr = CloudIPRanges({"json"})
        once = cipr._comparable_payload(payload)
        twice = cipr._comparable_payload(once)
        assert once == twice


class TestIPMergerProperties:
    @given(st.lists(cidr_v4, min_size=1, max_size=20))
    @fast
    def test_merge_preserves_coverage(self, cidrs: list) -> None:
        merger = IPMerger()
        networks = [ipaddress.ip_network(c, strict=False) for c in cidrs]
        merged = merger.merge_networks(networks)

        assert merged, "merging non-empty input must not be empty"
        # Coverage conservation: union(merged) == union(inputs).
        # collapse_addresses canonicalizes without materializing addresses.
        assert set(ipaddress.collapse_addresses(list(merged))) == set(ipaddress.collapse_addresses(list(networks)))

    @given(st.lists(cidr_v4, min_size=2, max_size=20))
    @fast
    def test_merged_networks_are_disjoint(self, cidrs: list) -> None:
        merger = IPMerger()
        networks = [ipaddress.ip_network(c, strict=False) for c in cidrs]
        merged = merger.merge_networks(networks)

        for i, a in enumerate(merged):
            for b in merged[i + 1 :]:
                assert not a.overlaps(b), f"{a} overlaps {b} — outputs must be disjoint"

    @given(
        st.lists(
            st.tuples(st.text(min_size=1, max_size=12), cidr_v4),
            min_size=1,
            max_size=15,
        )
    )
    @fast
    def test_provider_attribution_covers_all_inputs(self, pairs: list) -> None:
        merger = IPMerger()
        by_provider: dict[str, list[str]] = {}
        for pid, cidr in pairs:
            by_provider.setdefault(pid, []).append(cidr)
        for pid, cidrs in by_provider.items():
            merger.add_provider_data({
                "provider_id": pid,
                "provider": pid,
                "ipv4": cidrs,
                "ipv6": [],
            })

        output = merger.get_merged_output()
        merged_nets = [ipaddress.ip_network(c) for c in output["ipv4"]]
        ip_providers = output["ip_providers"]

        # Every published input CIDR is covered by exactly one merged network
        # carrying the publishing provider's id.
        for pid, cidrs in by_provider.items():
            for cidr in cidrs:
                net = ipaddress.ip_network(cidr)
                covering = [m for m in merged_nets if net.subnet_of(m)]
                assert len(covering) == 1
                assert pid in ip_providers[str(covering[0])]


class TestExtractCidrsProperties:
    @given(
        st.dictionaries(
            keys=st.sampled_from(["address", "ipPrefix", "cidr", "range", "addresses", "name", "id"]),
            values=st.one_of(cidr_v4, st.lists(cidr_v4, max_size=4), st.text(max_size=15)),
            max_size=8,
        )
    )
    @fast
    def test_finds_cidrs_under_matching_keys(self, data: dict) -> None:
        cipr = CloudIPRanges({"json"})
        found = set(cipr._extract_cidrs_from_json(data))
        for key, value in data.items():
            values = value if isinstance(value, list) else [value]
            for v in values:
                try:
                    net = str(ipaddress.ip_network(v, strict=False))
                except ValueError:
                    continue
                if any(hint in key.lower() for hint in ("ip", "cidr", "prefix", "range", "addr")):
                    assert net in found, f"CIDR {net} under key {key!r} was not extracted"
