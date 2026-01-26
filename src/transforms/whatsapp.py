import html
import io
import re
import urllib.parse
import zipfile
from typing import Any, Dict, List


def transform(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    result = cipr._transform_base(source_key, "https://developers.facebook.com/docs/whatsapp/guides/network-requirements/")

    data = None
    for url_str in re.findall(r"<a href=\"([^\"]+)\"", response[0].text):
        url_str = html.unescape(url_str)
        url_parsed = urllib.parse.urlparse(url_str)
        if (not url_parsed.hostname or not url_parsed.path) or (
            not re.search(r"\.fbcdn\.net$", url_parsed.hostname) or not re.search(r"\.zip$", url_parsed.path)
        ):
            continue

        r = cipr.session.get(url_str, timeout=10)
        r.raise_for_status()
        data = r.content
        break
    else:
        raise RuntimeError("No valid zip file found")

    zip_data = io.BytesIO(data)
    with zipfile.ZipFile(zip_data, "r") as zip_ref:
        for file in zip_ref.filelist:
            if "__MACOSX" in file.filename:
                continue

            if file.filename.endswith(".txt"):
                with zip_ref.open(file) as f:
                    for line in io.TextIOWrapper(f, encoding="utf-8"):
                        line = line.strip()
                        if line and not line.startswith("#"):
                            result["ipv4"].append(line)

    return result
