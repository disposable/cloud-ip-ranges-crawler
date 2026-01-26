import logging
from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    data = response[0].json()

    if isinstance(data, dict) and "ips" in data:
        for ip_dict in data["ips"]:
            if isinstance(ip_dict, dict) and "ip_address" in ip_dict:
                ip = ip_dict["ip_address"]
                if ":" in ip:
                    result["ipv6"].append(ip)
                else:
                    result["ipv4"].append(ip)
    else:
        logging.warning("Invalid Ahrefs response format")

    return result
