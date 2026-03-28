from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform PagerDuty webhook IP JSON responses.

    PagerDuty provides JSON endpoints for webhook IPs by service region:
    - US: https://developer.pagerduty.com/ip-safelists/webhooks-us-service-region-json
    - EU: https://developer.pagerduty.com/ip-safelists/webhooks-eu-service-region-json

    Note: PagerDuty recommends TLS/signature verification over IP safelisting.
    """
    result = cipr._transform_base(source_key)
    result["coverage_notes"] = "Webhook IPs for US and EU service regions. PagerDuty recommends TLS/signature verification over IP safelisting."

    ipv4 = set()
    ipv6 = set()

    for resp in response:
        try:
            data = resp.json()

            # Handle array of IP strings (simple format)
            if isinstance(data, list):
                for ip in data:
                    if isinstance(ip, str):
                        if ":" in ip:
                            ipv6.add(f"{ip}/128")
                        else:
                            ipv4.add(f"{ip}/32")

            # Handle object format with ipv4/ipv6 fields
            elif isinstance(data, dict):
                for ip in data.get("ipv4", []):
                    if isinstance(ip, str):
                        ipv4.add(f"{ip}/32")
                for ip in data.get("ipv6", []):
                    if isinstance(ip, str):
                        ipv6.add(f"{ip}/128")

        except Exception:
            pass  # nosec B110 - Continue if a response can't be parsed

    result["ipv4"] = sorted(ipv4)
    result["ipv6"] = sorted(ipv6)

    return result
