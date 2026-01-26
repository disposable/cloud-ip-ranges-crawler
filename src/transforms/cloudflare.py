from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)

    try:
        # Cloudflare API returns JSON with ipv4_cidrs and ipv6_cidrs
        data = response[0].json()

        if "result" in data:
            result["ipv4"] = data["result"].get("ipv4_cidrs", [])
            result["ipv6"] = data["result"].get("ipv6_cidrs", [])
        else:
            # Fallback for legacy format
            text_data = [r.text for r in response]
            if isinstance(text_data[0], str):
                result["ipv4"] = text_data[0].splitlines()
            if len(text_data) > 1 and isinstance(text_data[1], str):
                result["ipv6"] = text_data[1].splitlines()
    except (ValueError, AttributeError, KeyError):
        # Fallback: treat response as plain text
        text_data = [r.text for r in response]
        if isinstance(text_data[0], str):
            result["ipv4"] = text_data[0].splitlines()
        if len(text_data) > 1 and isinstance(text_data[1], str):
            result["ipv6"] = text_data[1].splitlines()

    return result
