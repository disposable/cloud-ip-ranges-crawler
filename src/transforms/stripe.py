from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)

    # Endpoints return JSON like {"API": ["ip", ...]} and {"WEBHOOKS": ["ip", ...]}
    for r in response:
        data = r.json()
        if not isinstance(data, dict):
            continue

        for key, values in data.items():
            if not isinstance(values, list):
                continue
            for ip in values:
                if not isinstance(ip, str):
                    continue
                # Stripe publishes individual IPs; normalize to /32 and /128.
                if "/" not in ip:
                    ip = f"{ip}/128" if ":" in ip else f"{ip}/32"
                if ":" in ip:
                    result["ipv6"].append(ip)
                else:
                    result["ipv4"].append(ip)

    return result
