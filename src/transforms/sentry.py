from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    data = response[0].text

    # Sentry uptime IPs API returns newline-separated plain text IPs
    # Each line contains a single IP address (not CIDR)
    if isinstance(data, str):
        for line in data.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            # Sentry returns bare IPs, normalize to /32 for IPv4
            if ":" in line:
                # IPv6 - keep as is or normalize to /128 if needed
                result["ipv6"].append(line)
            else:
                # IPv4 - normalize bare IP to /32 CIDR
                result["ipv4"].append(f"{line}/32")

    return result
