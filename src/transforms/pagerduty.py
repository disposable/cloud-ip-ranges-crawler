"""PagerDuty webhook IP ranges transform.

SCOPE: PagerDuty webhook IPs for US and EU service regions ONLY.
This covers incoming webhook traffic FROM PagerDuty TO customer systems.

EXPLICITLY COVERED:
- US Service Region webhook IPs
- EU Service Region webhook IPs

EXPLICITLY OUT OF SCOPE:
- REST API IPs (customer -> PagerDuty)
- Event API IPs
- Other PagerDuty services

Note: PagerDuty recommends TLS/signature verification over IP safelisting.
The webhook IPs are relatively stable but may change with notice.

API Endpoints:
- US: https://developer.pagerduty.com/ip-safelists/webhooks-us-service-region-json
- EU: https://developer.pagerduty.com/ip-safelists/webhooks-eu-service-region-json
"""

from typing import Any, Dict, List

# Supported response formats - fail clearly if format not recognized
SUPPORTED_FORMATS = {"array", "object"}


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform PagerDuty webhook IP responses with explicit region/surface tagging.

    Each IP is tagged with:
    - surface: "webhook" (incoming from PagerDuty)
    - region: "US" or "EU" based on source endpoint

    Raises ValueError for unrecognized response formats.
    """
    result = cipr._transform_base(source_key)
    result["coverage_notes"] = (
        "PagerDuty webhook IPs ONLY (US and EU service regions). "
        "Incoming webhooks FROM PagerDuty TO customer systems. "
        "REST API and Event API IPs are NOT included. "
        "PagerDuty recommends TLS/signature verification over IP safelisting."
    )

    # Define regions corresponding to response array positions
    # response[0] = US endpoint, response[1] = EU endpoint (if present)
    regions = ["US", "EU"]

    ipv4_details = []
    ipv6_details = []
    ipv4_set = set()
    ipv6_set = set()

    for idx, resp in enumerate(response):
        region = regions[idx] if idx < len(regions) else f"UNKNOWN_{idx}"

        try:
            data = resp.json()
        except Exception as e:
            raise ValueError(f"Failed to parse PagerDuty {region} response: invalid JSON") from e

        # Handle array of IP strings (standard format from PagerDuty)
        if isinstance(data, list):
            for ip in data:
                if not isinstance(ip, str):
                    continue
                _add_ip_with_metadata(ip, region, "webhook", ipv4_set, ipv6_set, ipv4_details, ipv6_details)

        # Handle object format with ipv4/ipv6 fields (alternative format)
        elif isinstance(data, dict):
            # Must have at least one recognized key to be valid
            has_ipv4 = "ipv4" in data and isinstance(data.get("ipv4"), list)
            has_ipv6 = "ipv6" in data and isinstance(data.get("ipv6"), list)

            if not has_ipv4 and not has_ipv6:
                raise ValueError(f"Unrecognized PagerDuty {region} dict format: missing 'ipv4' or 'ipv6' keys. Got keys: {list(data.keys())}")

            if has_ipv4:
                for ip in data["ipv4"]:
                    if isinstance(ip, str):
                        _add_ip_with_metadata(ip, region, "webhook", ipv4_set, ipv6_set, ipv4_details, ipv6_details)
            if has_ipv6:
                for ip in data["ipv6"]:
                    if isinstance(ip, str):
                        _add_ip_with_metadata(ip, region, "webhook", ipv4_set, ipv6_set, ipv4_details, ipv6_details)

        else:
            # Fail clearly on unrecognized format
            raise ValueError(f"Unrecognized PagerDuty {region} response format: {type(data).__name__}. Expected list or dict.")

    result["ipv4"] = sorted(ipv4_set)
    result["ipv6"] = sorted(ipv6_set)
    if ipv4_details:
        result["details_ipv4"] = ipv4_details
    if ipv6_details:
        result["details_ipv6"] = ipv6_details

    return result


def _add_ip_with_metadata(ip: str, region: str, surface: str, ipv4_set: set, ipv6_set: set, ipv4_details: List[Dict], ipv6_details: List[Dict]) -> None:
    """Add IP with surface and region metadata.

    Args:
        ip: IP address string
        region: "US" or "EU"
        surface: "webhook" for incoming webhooks
        ipv4_set: Set to track unique IPv4 addresses
        ipv6_set: Set to track unique IPv6 addresses
        ipv4_details: List to append IPv4 metadata
        ipv6_details: List to append IPv6 metadata
    """
    if ":" in ip:
        cidr = f"{ip}/128"
        if cidr not in ipv6_set:
            ipv6_set.add(cidr)
            ipv6_details.append({
                "address": cidr,
                "region": region,
                "surface": surface,
            })
    else:
        cidr = f"{ip}/32"
        if cidr not in ipv4_set:
            ipv4_set.add(cidr)
            ipv4_details.append({
                "address": cidr,
                "region": region,
                "surface": surface,
            })
