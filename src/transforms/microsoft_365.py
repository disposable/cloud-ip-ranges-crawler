import re
from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform Microsoft 365 endpoints web service response to extract IP ranges.

    The Microsoft 365 IP Address and URL web service returns an array of endpoint sets,
    each containing IP address ranges in the 'ips' field.

    Reference: https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service
    """
    result = cipr._transform_base(source_key)
    result["details_ipv4"] = []
    result["details_ipv6"] = []

    # First, extract ClientRequestId from documentation page
    doc_html = response[0].text

    # Look for GUID pattern in URLs (e.g., ClientRequestId=b10c5ed1-bad1-445f-b386-b919946339a7)
    guid_pattern = re.compile(r"\?clientrequestid=([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})", re.IGNORECASE)
    match = guid_pattern.search(doc_html)

    if match:
        client_request_id = match.group(1)
    else:
        # Fallback to example GUID from docs if not found
        client_request_id = "b10c5ed1-bad1-445f-b386-b919946339a7"

    # Build the actual API URL with the extracted ClientRequestId
    api_url = f"https://endpoints.office.com/endpoints/worldwide?clientrequestid={client_request_id}"

    # Fetch the actual endpoints data
    api_response = cipr.session.get(api_url, timeout=10)
    api_response.raise_for_status()

    data = api_response.json()

    if not isinstance(data, list):
        raise ValueError(f"Expected JSON array from Microsoft 365 API, got {type(data).__name__}")

    ipv4 = set()
    ipv6 = set()
    details_ipv4 = []
    details_ipv6 = []

    for endpoint_set in data:
        if not isinstance(endpoint_set, dict):
            continue

        ips = endpoint_set.get("ips", [])
        service_area = endpoint_set.get("serviceArea", "")
        category = endpoint_set.get("category", "")

        if not isinstance(ips, list):
            continue

        for ip in ips:
            if not isinstance(ip, str):
                continue

            if ":" in ip:
                ipv6.add(ip)
                details_ipv6.append({"address": ip, "serviceArea": service_area, "category": category})
            else:
                ipv4.add(ip)
                details_ipv4.append({"address": ip, "serviceArea": service_area, "category": category})

    result["ipv4"] = list(ipv4)
    result["ipv6"] = list(ipv6)
    if details_ipv4:
        result["details_ipv4"] = details_ipv4
    if details_ipv6:
        result["details_ipv6"] = details_ipv6

    # Update source to reflect the actual API URL used
    result["source"] = api_url

    return result
