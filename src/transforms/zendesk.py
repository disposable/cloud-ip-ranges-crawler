from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    data = response[0].json()
    ips = data.get("ips", {}) if isinstance(data, dict) else {}

    ingress = ips.get("ingress", {}) if isinstance(ips, dict) else {}
    egress = ips.get("egress", {}) if isinstance(ips, dict) else {}
    cidr_list: List[str] = []
    for bucket in (ingress, egress):
        if isinstance(bucket, dict):
            for key in ("all", "specific"):
                v = bucket.get(key)
                if isinstance(v, list):
                    cidr_list.extend([x for x in v if isinstance(x, str)])

    if not cidr_list:
        cidr_list = cipr._extract_cidrs_from_json(data)

    for cidr in cidr_list:
        if ":" in cidr:
            result["ipv6"].append(cidr)
        else:
            result["ipv4"].append(cidr)
    return result
