import io
import zipfile
from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key)
    data = response[0].content

    zip_data = io.BytesIO(data)
    with zipfile.ZipFile(zip_data, "r") as zip_ref:
        with zip_ref.open("akamai_ipv4_CIDRs.txt") as f:
            for line in io.TextIOWrapper(f, encoding="utf-8"):
                line = line.strip()
                if line and not line.startswith("#"):
                    result["ipv4"].append(line)

        with zip_ref.open("akamai_ipv6_CIDRs.txt") as f:
            for line in io.TextIOWrapper(f, encoding="utf-8"):
                line = line.strip()
                if line and not line.startswith("#"):
                    result["ipv6"].append(line)

    return result
