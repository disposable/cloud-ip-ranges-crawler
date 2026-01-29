"""IP network merging and provider tracking functionality."""

import ipaddress
from datetime import datetime
from typing import Any, Dict, List, Set, Union


class IPMerger:
    """Handles IP network merging and provider tracking for all-providers output."""

    def __init__(self) -> None:
        self._merged_ipv4: Set[ipaddress.IPv4Network] = set()
        self._merged_ipv6: Set[ipaddress.IPv6Network] = set()
        self._merged_providers: List[Dict[str, Any]] = []
        self._ip_providers: Dict[Union[ipaddress.IPv4Network, ipaddress.IPv6Network], Set[str]] = {}

    def reset(self) -> None:
        """Reset all tracking data."""
        self._merged_ipv4.clear()
        self._merged_ipv6.clear()
        self._merged_providers.clear()
        self._ip_providers.clear()

    def add_provider_data(self, transformed_data: Dict[str, Any]) -> None:
        """Add IP ranges from a provider and track which provider contributed each range."""
        provider_id = transformed_data.get("provider_id", "unknown")

        # Track providers for each IP range using ipaddress objects
        for ip_str in transformed_data.get("ipv4", []):
            try:
                ip_network = ipaddress.IPv4Network(ip_str, strict=False)
                if ip_network not in self._ip_providers:
                    self._ip_providers[ip_network] = set()
                self._ip_providers[ip_network].add(provider_id)
                self._merged_ipv4.add(ip_network)
            except ValueError:
                continue

        for ip_str in transformed_data.get("ipv6", []):
            try:
                ip_network = ipaddress.IPv6Network(ip_str, strict=False)
                if ip_network not in self._ip_providers:
                    self._ip_providers[ip_network] = set()
                self._ip_providers[ip_network].add(provider_id)
                self._merged_ipv6.add(ip_network)
            except ValueError:
                continue

        # Track provider summary
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

    def merge_networks(self, networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """Merge overlapping IP networks using ipaddress module."""
        if not networks:
            return []

        # Separate IPv4 and IPv6 networks
        ipv4_networks = []
        ipv6_networks = []

        for network in networks:
            if network.version == 4:
                ipv4_networks.append(network)
            else:
                ipv6_networks.append(network)

        # Merge IPv4 and IPv6 separately
        merged_ipv4 = self._merge_same_version_v4(ipv4_networks)
        merged_ipv6 = self._merge_same_version_v6(ipv6_networks)

        return merged_ipv4 + merged_ipv6

    @staticmethod
    def _networks_are_neighboring(net1: Union[ipaddress.IPv4Network, ipaddress.IPv6Network], net2: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]) -> bool:
        """Check if two networks are neighboring (can be merged into a supernet)."""
        if net1.version != net2.version:
            return False

        # For IPv4, check if networks are consecutive blocks
        if net1.version == 4:
            # Check if one network ends exactly where the other begins
            try:
                if net1.broadcast_address + 1 == net2.network_address:
                    return True
                if net2.broadcast_address + 1 == net1.network_address:
                    return True
            except (ipaddress.AddressValueError, OverflowError):
                # Handle overflow cases
                pass

        # For IPv6, check if networks are consecutive blocks
        else:
            # Check if one network ends exactly where the other begins
            try:
                if int(net1.broadcast_address) + 1 == int(net2.network_address):
                    return True
                if int(net2.broadcast_address) + 1 == int(net1.network_address):
                    return True
            except (ipaddress.AddressValueError, OverflowError):
                # Handle overflow cases
                pass

        return False

    @staticmethod
    def _merge_same_version_v4(networks_list: List[ipaddress.IPv4Network]) -> List[ipaddress.IPv4Network]:
        """Merge IPv4 networks."""
        if not networks_list:
            return []

        # Sort by network address
        networks_list.sort(key=lambda x: x.network_address)

        # Merge overlapping networks
        merged = []
        for network in networks_list:
            if not merged:
                merged.append(network)
                continue

            last_merged = merged[-1]
            if network.overlaps(last_merged) or IPMerger._networks_are_neighboring(network, last_merged):
                # Merge by taking the superset
                if network.supernet_of(last_merged):
                    merged[-1] = network
                elif last_merged.supernet_of(network):
                    # Keep last_merged as it's already the superset
                    pass
                else:
                    # Find the minimal network that encompasses both
                    start_addr = min(network.network_address, last_merged.network_address)
                    end_addr = max(network.broadcast_address, last_merged.broadcast_address)

                    # Find the smallest prefix that covers both networks
                    merged_network = network
                    while not (merged_network.network_address <= start_addr and merged_network.broadcast_address >= end_addr):
                        merged_network = merged_network.supernet()
                    merged[-1] = merged_network
            else:
                merged.append(network)

        return merged

    @staticmethod
    def _merge_same_version_v6(networks_list: List[ipaddress.IPv6Network]) -> List[ipaddress.IPv6Network]:
        """Merge IPv6 networks."""
        if not networks_list:
            return []

        # Sort by network address
        networks_list.sort(key=lambda x: x.network_address)

        # Merge overlapping networks
        merged = []
        for network in networks_list:
            if not merged:
                merged.append(network)
                continue

            last_merged = merged[-1]
            if network.overlaps(last_merged) or IPMerger._networks_are_neighboring(network, last_merged):
                # Merge by taking the superset
                if network.supernet_of(last_merged):
                    merged[-1] = network
                elif last_merged.supernet_of(network):
                    # Keep last_merged as it's already the superset
                    pass
                else:
                    # Find the minimal network that encompasses both
                    start_addr = min(network.network_address, last_merged.network_address)
                    end_addr = max(network.broadcast_address, last_merged.broadcast_address)

                    # Find the smallest prefix that covers both networks
                    merged_network = network
                    while not (merged_network.network_address <= start_addr and merged_network.broadcast_address >= end_addr):
                        merged_network = merged_network.supernet()
                    merged[-1] = merged_network
            else:
                merged.append(network)

        return merged

    def get_merged_output(self) -> Dict[str, Any]:
        """Get the merged output data with provider information."""
        if not self._merged_providers:
            return {}

        generated_at = datetime.now().isoformat()

        # Merge overlapping IP networks
        all_networks = list(self._merged_ipv4) + list(self._merged_ipv6)
        merged_networks = self.merge_networks(all_networks)

        # Separate merged networks by version
        merged_ipv4 = [net for net in merged_networks if net.version == 4]
        merged_ipv6 = [net for net in merged_networks if net.version == 6]

        # Create IP to providers mapping for merged networks
        merged_ip_providers: Dict[Union[ipaddress.IPv4Network, ipaddress.IPv6Network], Set[str]] = {}

        # For each merged network, find all original networks that are covered by it
        for merged_network in merged_networks:
            providers_for_network = set()

            # Check all original IP ranges that this merged network covers
            for original_network, providers in self._ip_providers.items():
                # Only compare networks of the same version
                if merged_network.version == original_network.version:
                    if merged_network.version == 4:
                        # Both are IPv4 networks
                        merged_ipv4_net = ipaddress.IPv4Network(str(merged_network), strict=False)
                        original_ipv4 = ipaddress.IPv4Network(str(original_network), strict=False)
                        if merged_ipv4_net.supernet_of(original_ipv4) or merged_ipv4_net.overlaps(original_ipv4):
                            providers_for_network.update(providers)
                    else:
                        # Both are IPv6 networks
                        merged_ipv6_net = ipaddress.IPv6Network(str(merged_network), strict=False)
                        original_ipv6 = ipaddress.IPv6Network(str(original_network), strict=False)
                        if merged_ipv6_net.supernet_of(original_ipv6) or merged_ipv6_net.overlaps(original_ipv6):
                            providers_for_network.update(providers)

            merged_ip_providers[merged_network] = providers_for_network

        # Prepare merged payload with provider information
        merged_payload = {
            "provider": "All Providers",
            "generated_at": generated_at,
            "provider_count": len(self._merged_providers),
            "providers": self._merged_providers,
            "ipv4": [str(net) for net in merged_ipv4],
            "ipv6": [str(net) for net in merged_ipv6],
            "ip_providers": {str(net): sorted(providers) for net, providers in merged_ip_providers.items()},
        }

        return merged_payload

    @property
    def has_data(self) -> bool:
        """Check if any provider data has been added."""
        return bool(self._merged_providers)

    @property
    def provider_count(self) -> int:
        """Get the number of providers that contributed data."""
        return len(self._merged_providers)
