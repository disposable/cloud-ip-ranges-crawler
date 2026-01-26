import ipaddress
import logging
from typing import Any, Dict, List, Set, Tuple

from defusedxml import ElementTree as ET


def _xml_find_text(root: Any, tag_local: str) -> str | None:
    """Find text content for a given tag in XML."""
    for el in root.iter():
        if el.tag.endswith("}" + tag_local) and el.text:
            return el.text
    return None


def _extract_org_handles(rdap_data: Dict[str, Any]) -> Set[str]:
    """Extract organization handles from RDAP response."""
    org_handles: Set[str] = set()
    entities = rdap_data.get("entities", [])

    if not isinstance(entities, list):
        return org_handles

    for e in entities:
        if not isinstance(e, dict):
            continue

        roles = e.get("roles", [])
        handle = e.get("handle")

        if isinstance(roles, list) and "registrant" in roles and isinstance(handle, str) and handle:
            org_handles.add(handle)
            break

    return org_handles


def _parse_org_response(org_r: Any, result: Dict[str, Any]) -> str | None:
    """Parse organization response and extract update date."""
    try:
        org_data = org_r.json()
        if result.get("source_updated_at") is None:
            return org_data.get("org", {}).get("updateDate")
    except Exception:
        try:
            org_root = ET.fromstring(org_r.text)
            if result.get("source_updated_at") is None:
                return _xml_find_text(org_root, "updateDate")
        except Exception as e:
            logging.warning("Failed to parse ARIN org response (both JSON and XML): %s", e)

    return None


def _parse_nets_response(nets_r: Any, handle: str) -> List[Tuple[str, str]]:
    """Parse networks response and extract address ranges."""
    all_nets: List[Tuple[str, str]] = []

    try:
        nets_data = nets_r.json()
        nets = nets_data.get("nets", {}).get("netRef", [])

        if isinstance(nets, list):
            for net in nets:
                if not isinstance(net, dict):
                    continue
                start = net.get("@startAddress") or net.get("startAddress")
                end = net.get("@endAddress") or net.get("endAddress")
                if start and end:
                    all_nets.append((start, end))
    except Exception:
        try:
            nets_root = ET.fromstring(nets_r.text)
            for el in nets_root.iter():
                if not el.tag.endswith("}" + "netRef"):
                    continue
                start = el.attrib.get("startAddress")
                end = el.attrib.get("endAddress")
                if start and end:
                    all_nets.append((start, end))
        except Exception as e:
            logging.error("Failed to parse ARIN nets for %s (both JSON and XML): %s", handle, e)
            logging.error("Response body: %s", nets_r.text[:500])
            raise RuntimeError(f"ARIN nets could not be parsed for {handle}")

    return all_nets


def _convert_ranges_to_cidrs(all_nets: List[Tuple[str, str]]) -> Tuple[List[str], List[str]]:
    """Convert IP address ranges to CIDR notation."""
    ipv4: List[str] = []
    ipv6: List[str] = []
    seen: Set[Tuple[str, str]] = set()

    for start, end in all_nets:
        if (start, end) in seen:
            continue
        seen.add((start, end))

        try:
            start_ip = ipaddress.ip_address(start)
            end_ip = ipaddress.ip_address(end)
        except ValueError:
            continue

        for net in ipaddress.summarize_address_range(start_ip, end_ip):
            cidr = str(net)
            if ":" in cidr:
                ipv6.append(cidr)
            else:
                ipv4.append(cidr)

    return ipv4, ipv6


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform RDAP registry response into IP ranges."""
    seeds = cipr.sources[source_key]
    result = cipr._transform_base(
        source_key,
        [f"https://rdap.arin.net/registry/ip/{seed.split('/')[0]}" for seed in seeds],
    )
    result["method"] = "rdap_registry"
    result["coverage_notes"] = "Provider-owned netblocks (registry), not necessarily the full set of edge/egress IPs"

    # Extract organization handles from initial RDAP responses
    org_handles: Set[str] = set()
    for r in response:
        rdap = r.json()
        org_handles.update(_extract_org_handles(rdap))

    if not org_handles:
        raise RuntimeError(f"Failed to find any ARIN org handles for {source_key} from seeds: {seeds}")

    # Fetch organization and network details
    all_nets: List[Tuple[str, str]] = []
    for handle in org_handles:
        org_url = f"https://whois.arin.net/rest/org/{handle}"
        nets_url = f"https://whois.arin.net/rest/org/{handle}/nets"

        org_r = cipr.session.get(org_url, timeout=10)
        org_r.raise_for_status()
        nets_r = cipr.session.get(nets_url, timeout=10)
        nets_r.raise_for_status()

        # Parse organization response for update date
        update_date = _parse_org_response(org_r, result)
        if update_date and result.get("source_updated_at") is None:
            result["source_updated_at"] = update_date

        # Parse networks response
        all_nets.extend(_parse_nets_response(nets_r, handle))

    # Convert address ranges to CIDR notation
    ipv4, ipv6 = _convert_ranges_to_cidrs(all_nets)
    result["ipv4"] = ipv4
    result["ipv6"] = ipv6

    return result
