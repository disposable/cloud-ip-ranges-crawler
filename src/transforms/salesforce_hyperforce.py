from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    data = response[0].json()

    # Expected shape:
    # {"syncToken": "...", "createDate": "YYYY-MM-DD-hh-mm-ss", "prefixes": [{"region": "...", "provider": "aws", "ip_prefix": ["CIDR", ...]}, ...]}
    if isinstance(data, dict):
        result["source_updated_at"] = data.get("createDate")
        prefixes = data.get("prefixes")
        if isinstance(prefixes, list):
            for entry in prefixes:
                if not isinstance(entry, dict):
                    continue
                ip_prefix = entry.get("ip_prefix")
                if not isinstance(ip_prefix, list):
                    continue
                for cidr in ip_prefix:
                    if not isinstance(cidr, str):
                        continue
                    if ":" in cidr:
                        result["ipv6"].append(cidr)
                    else:
                        result["ipv4"].append(cidr)

    return result
