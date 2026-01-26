from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)

    # We only include INTERCOM-OUTBOUND (webhooks). JSON shape:
    # {"ip_ranges": [{"range": "1.2.3.4/32", "region": "US", "service": "INTERCOM-OUTBOUND"}, ...], "date": "YYYY-MM-DD"}
    for r in response:
        data = r.json()
        if not isinstance(data, dict):
            continue
        if date := data.get("date"):
            result["source_updated_at"] = date

        ip_ranges = data.get("ip_ranges")
        if not isinstance(ip_ranges, list):
            continue

        for entry in ip_ranges:
            if not isinstance(entry, dict):
                continue
            if entry.get("service") != "INTERCOM-OUTBOUND":
                continue
            cidr = entry.get("range")
            if not isinstance(cidr, str):
                continue
            if ":" in cidr:
                result["ipv6"].append(cidr)
            else:
                result["ipv4"].append(cidr)

    return result
