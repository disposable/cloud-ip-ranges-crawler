"""IP network merging and provider tracking functionality."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Dict, List, Literal, MutableMapping, Sequence, Set, Tuple, TypeVar, Union, overload

IPvXNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
TNet = TypeVar("TNet", ipaddress.IPv4Network, ipaddress.IPv6Network)


class IPMerger:
    """Handles IP network merging and provider tracking for all-providers output."""

    def __init__(self) -> None:
        self._merged_providers: List[Dict[str, Any]] = []
        # Map of ORIGINAL networks -> set(provider_id)
        self._ip_providers: Dict[IPvXNetwork, Set[str]] = {}

    def reset(self) -> None:
        """Reset all tracking data."""
        self._merged_providers.clear()
        self._ip_providers.clear()

    def add_provider_data(self, transformed_data: Dict[str, Any]) -> None:
        """Add IP ranges from a provider and track which provider contributed each range."""
        provider_id = transformed_data.get("provider_id", "unknown")

        for ip_str in transformed_data.get("ipv4", []):
            try:
                net = ipaddress.IPv4Network(ip_str, strict=False)
            except ValueError:
                continue
            self._ip_providers.setdefault(net, set()).add(provider_id)

        for ip_str in transformed_data.get("ipv6", []):
            try:
                net = ipaddress.IPv6Network(ip_str, strict=False)
            except ValueError:
                continue
            self._ip_providers.setdefault(net, set()).add(provider_id)

        provider_summary = {
            "provider": transformed_data.get("provider"),
            "provider_id": transformed_data.get("provider_id"),
            "method": transformed_data.get("method"),
            "source": transformed_data.get("source"),
            "last_update": transformed_data.get("last_update"),
            "ipv4_count": len(transformed_data.get("ipv4", [])),
            "ipv6_count": len(transformed_data.get("ipv6", [])),
        }
        self._merged_providers.append(provider_summary)

    def merge_networks(self, networks: Sequence[IPvXNetwork]) -> List[IPvXNetwork]:
        """Merge/collapse IP networks without widening coverage."""
        if not networks:
            return []

        ipv4 = [n for n in networks if n.version == 4]
        ipv6 = [n for n in networks if n.version == 6]

        merged_ipv4 = self._merge_same_version_v4(ipv4)
        merged_ipv6 = self._merge_same_version_v6(ipv6)

        # Keep output order as: IPv4 first, then IPv6 (matches the original behavior).
        return merged_ipv4 + merged_ipv6

    @staticmethod
    def _networks_are_neighboring(net1: IPvXNetwork, net2: IPvXNetwork) -> bool:
        """Check if two networks are directly adjacent.

        Kept for drop-in compatibility; not used by the new collapsing algorithm.
        """
        if net1.version != net2.version:
            return False
        try:
            return int(net1.broadcast_address) + 1 == int(net2.network_address) or int(net2.broadcast_address) + 1 == int(net1.network_address)
        except (ipaddress.AddressValueError, OverflowError):
            return False

    @staticmethod
    def _merge_same_version_v4(networks_list: List[ipaddress.IPv4Network]) -> List[ipaddress.IPv4Network]:
        """Collapse IPv4 networks without widening coverage."""
        if not networks_list:
            return []
        collapsed = list(ipaddress.collapse_addresses(networks_list))
        collapsed.sort(key=lambda n: (int(n.network_address), n.prefixlen))
        return collapsed

    @staticmethod
    def _merge_same_version_v6(networks_list: List[ipaddress.IPv6Network]) -> List[ipaddress.IPv6Network]:
        """Collapse IPv6 networks without widening coverage."""
        if not networks_list:
            return []
        collapsed = list(ipaddress.collapse_addresses(networks_list))
        collapsed.sort(key=lambda n: (int(n.network_address), n.prefixlen))
        return collapsed

    @staticmethod
    @overload
    def _sorted_original_items(
        ip_providers: MutableMapping[IPvXNetwork, Set[str]],
        version: Literal[4],
    ) -> Sequence[Tuple[ipaddress.IPv4Network, Set[str]]]:
        pass

    @staticmethod
    @overload
    def _sorted_original_items(
        ip_providers: MutableMapping[IPvXNetwork, Set[str]],
        version: Literal[6],
    ) -> Sequence[Tuple[ipaddress.IPv6Network, Set[str]]]: ...

    @staticmethod
    def _sorted_original_items(
        ip_providers: MutableMapping[IPvXNetwork, Set[str]],
        version: Literal[4, 6],
    ) -> Sequence[Tuple[IPvXNetwork, Set[str]]]:
        """Return original networks of a given IP version sorted by (start, prefixlen)."""
        if version == 4:
            items: List[Tuple[IPvXNetwork, Set[str]]] = [(net, providers) for net, providers in ip_providers.items() if isinstance(net, ipaddress.IPv4Network)]
        else:
            items = [(net, providers) for net, providers in ip_providers.items() if isinstance(net, ipaddress.IPv6Network)]

        items.sort(key=lambda kv: (int(kv[0].network_address), kv[0].prefixlen))
        return items

    @staticmethod
    def _map_providers_to_collapsed(
        originals: Sequence[Tuple[TNet, Set[str]]],
        collapsed: Sequence[TNet],
    ) -> Dict[TNet, Set[str]]:
        """Assign providers from original networks to collapsed networks in a single pass."""
        out: Dict[TNet, Set[str]] = {net: set() for net in collapsed}
        if not originals or not collapsed:
            return out

        j = 0
        for orig_net, providers in originals:
            # Advance until the current collapsed net could possibly contain this original.
            while j < len(collapsed) and int(orig_net.network_address) > int(collapsed[j].broadcast_address):
                j += 1

            # Find a collapsed net that contains the original net.
            k = j
            while k < len(collapsed) and not orig_net.subnet_of(collapsed[k]):
                k += 1

            if k < len(collapsed):
                out[collapsed[k]].update(providers)
                j = k  # monotonic pointer

        return out

    def get_merged_output(self) -> Dict[str, Any]:
        """Get the merged output data with provider information."""
        if not self._merged_providers:
            return {}

        generated_at = datetime.now().isoformat()

        # Collapse ORIGINAL networks (dict keys are authoritative).
        all_networks: List[IPvXNetwork] = list(self._ip_providers.keys())
        merged_networks = self.merge_networks(all_networks)

        merged_ipv4: List[ipaddress.IPv4Network] = [net for net in merged_networks if net.version == 4]  # type: ignore[list-item]
        merged_ipv6: List[ipaddress.IPv6Network] = [net for net in merged_networks if net.version == 6]  # type: ignore[list-item]

        # Provider attribution (fast single pass per version)
        orig_v4 = self._sorted_original_items(self._ip_providers, version=4)
        orig_v6 = self._sorted_original_items(self._ip_providers, version=6)

        v4_map = self._map_providers_to_collapsed(orig_v4, merged_ipv4)
        v6_map = self._map_providers_to_collapsed(orig_v6, merged_ipv6)

        # Deterministic combined order: IPv4, then IPv6 (matching `ipv4`/`ipv6` lists).
        merged_ip_providers: Dict[IPvXNetwork, Set[str]] = {}
        for net in merged_ipv4:
            merged_ip_providers[net] = v4_map.get(net, set())
        for net in merged_ipv6:
            merged_ip_providers[net] = v6_map.get(net, set())

        return {
            "provider": "All Providers",
            "generated_at": generated_at,
            "provider_count": len(self._merged_providers),
            "providers": self._merged_providers,
            "ipv4": [str(net) for net in merged_ipv4],
            "ipv6": [str(net) for net in merged_ipv6],
            "ip_providers": {str(net): sorted(providers) for net, providers in merged_ip_providers.items()},
        }

    @property
    def has_data(self) -> bool:
        """Check if any provider data has been added."""
        return bool(self._merged_providers)

    @property
    def provider_count(self) -> int:
        """Get the number of providers that contributed data."""
        return len(self._merged_providers)
