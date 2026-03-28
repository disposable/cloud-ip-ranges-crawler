from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    ipv4: set[str] = set()
    ipv6: set[str] = set()

    for r in response:
        try:
            # Cloudflare API returns JSON with ipv4_cidrs and ipv6_cidrs.
            data = r.json()
            if isinstance(data, dict) and "result" in data:
                api_result = data.get("result", {})
                ipv4.update(api_result.get("ipv4_cidrs", []) or [])
                ipv6.update(api_result.get("ipv6_cidrs", []) or [])
                # JD Cloud endpoint can return cidrs in jdcloud_cidrs.
                for cidr in api_result.get("jdcloud_cidrs", []) or []:
                    if ":" in cidr:
                        ipv6.add(cidr)
                    else:
                        ipv4.add(cidr)
                continue
        except (ValueError, AttributeError, KeyError, TypeError):
            pass

        # Text endpoints (ips-v4 / ips-v6) return one CIDR per line.
        for line in (r.text or "").splitlines():
            cidr = line.strip()
            if not cidr:
                continue
            if ":" in cidr:
                ipv6.add(cidr)
            else:
                ipv4.add(cidr)

    result["ipv4"] = sorted(ipv4)
    result["ipv6"] = sorted(ipv6)

    return result
