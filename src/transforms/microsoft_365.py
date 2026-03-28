"""Microsoft 365 endpoints web service transform.

SCOPE: Microsoft 365 endpoint IP ranges from the official web service.
This is Microsoft 365-specific endpoint data, NOT universal Microsoft network coverage.

API FLOW:
1. Generate local UUID per request (NOT scraped from docs)
2. Check version endpoint first to detect changes
3. Fetch endpoints only when version indicates updates
4. Preserve endpoint metadata: serviceArea, category, endpoint IDs

References:
- https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service
- Version endpoint: /version/worldwide
- Endpoints endpoint: /endpoints/worldwide

OUT OF SCOPE:
- Azure service tags (separate source: microsoft_azure)
- General Microsoft network ranges
- Non-Worldwide instances (GovCloud, China, etc.)
"""

import uuid
from typing import Any, Dict, List

# API base URL
M365_API_BASE = "https://endpoints.office.com"


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform Microsoft 365 endpoints web service response.

    Implements the proper web service flow:
    1. Generate local UUID per request
    2. Check version endpoint for updates
    3. Fetch endpoints payload when needed
    4. Preserve metadata (serviceArea, category, endpoint IDs)

    This is Microsoft 365 endpoint data only - NOT Azure or general Microsoft IPs.
    """
    result = cipr._transform_base(source_key)
    result["details_ipv4"] = []
    result["details_ipv6"] = []
    result["coverage_notes"] = (
        "Microsoft 365 Worldwide instance endpoints ONLY. "
        "Includes Exchange, SharePoint, Skype, Common services. "
        "Does NOT include Azure service tags or general Microsoft networks."
    )

    # Generate local UUID per request - do NOT scrape from docs
    client_request_id = str(uuid.uuid4())

    # Check version endpoint first
    version_url = f"{M365_API_BASE}/version/worldwide?clientrequestid={client_request_id}"

    try:
        version_response = cipr.session.get(version_url, timeout=10)
        version_response.raise_for_status()
        version_data = version_response.json()

        # Extract version metadata
        latest_version = version_data.get("latest", "unknown")
        result["source_updated_at"] = latest_version
    except Exception:
        # If version check fails, proceed anyway - we'll try to fetch endpoints
        latest_version = "unknown"

    # Fetch endpoints payload
    endpoints_url = f"{M365_API_BASE}/endpoints/worldwide?clientrequestid={client_request_id}"

    try:
        api_response = cipr.session.get(endpoints_url, timeout=30)
        api_response.raise_for_status()
        data = api_response.json()
    except Exception as e:
        raise RuntimeError(f"Failed to fetch Microsoft 365 endpoints: {e}") from e

    if not isinstance(data, list):
        raise ValueError(f"Expected JSON array from Microsoft 365 API, got {type(data).__name__}")

    # Process endpoint data with full metadata preservation
    ipv4 = set()
    ipv6 = set()
    details_ipv4 = []
    details_ipv6 = []

    for endpoint_set in data:
        if not isinstance(endpoint_set, dict):
            continue

        # Extract endpoint metadata
        endpoint_id = endpoint_set.get("id", "")
        service_area = endpoint_set.get("serviceArea", "")
        category = endpoint_set.get("category", "")
        required = endpoint_set.get("required", False)
        tcp_ports = endpoint_set.get("tcpPorts", "")
        udp_ports = endpoint_set.get("udpPorts", "")

        ips = endpoint_set.get("ips", [])
        if not isinstance(ips, list):
            continue

        for ip in ips:
            if not isinstance(ip, str):
                continue

            # Build detail entry with full metadata
            detail = {
                "address": ip,
                "serviceArea": service_area,
                "category": category,
                "endpointId": endpoint_id,
                "required": required,
            }
            if tcp_ports:
                detail["tcpPorts"] = tcp_ports
            if udp_ports:
                detail["udpPorts"] = udp_ports

            if ":" in ip:
                ipv6.add(ip)
                details_ipv6.append(detail)
            else:
                ipv4.add(ip)
                details_ipv4.append(detail)

    result["ipv4"] = sorted(ipv4)
    result["ipv6"] = sorted(ipv6)
    if details_ipv4:
        result["details_ipv4"] = details_ipv4
    if details_ipv6:
        result["details_ipv6"] = details_ipv6

    # Document the actual API URLs used
    result["source"] = [version_url, endpoints_url]

    return result
