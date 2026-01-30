"""ASN-based source handling with RADB AS-SET expansion."""

import logging
import re
import socket
from functools import lru_cache
from typing import Any, Dict, List, Set

from transforms.common import validate_ip

# RADB whois configuration
_RADB_HOST = "whois.radb.net"
_RADB_PORT = 43


@lru_cache(maxsize=256)
def radb_whois_query(query: str) -> str:
    """Query RADB whois server."""
    q = query.strip()
    if not q:
        raise ValueError("RADB query must not be empty")

    with socket.create_connection((_RADB_HOST, _RADB_PORT), timeout=10) as s:
        s.sendall((q + "\r\n").encode("utf-8"))
        chunks: list[bytes] = []
        while True:
            buf = s.recv(4096)
            if not buf:
                break
            chunks.append(buf)

    return b"".join(chunks).decode("utf-8", errors="replace")


def _radb_extract_members(whois_text: str) -> list[str]:
    """Extract members from RADB whois response."""
    members: list[str] = []
    current_attr: str | None = None

    for raw_line in whois_text.splitlines():
        line = raw_line.rstrip("\r")
        if not line.strip():
            current_attr = None
            continue

        cont = line[:1].isspace()
        if cont and current_attr in {"members", "mp-members"}:
            value = line.strip()
        else:
            m = re.match(r"^(members|mp-members):\s*(.*)$", line, flags=re.IGNORECASE)
            if not m:
                current_attr = None
                continue
            current_attr = m.group(1).lower()
            value = m.group(2).strip()

        if not value:
            continue

        for token in re.split(r"[\s,]+", value):
            t = token.strip()
            if t:
                members.append(t)

    return members


def radb_resolve_as_set(as_set: str, *, max_depth: int = 5) -> Set[str]:
    """Resolve RADB AS-SET to individual ASNs."""
    root = as_set.strip().upper()
    if not root:
        raise ValueError("AS-SET must not be empty")

    seen_sets: Set[str] = set()
    out_asns: Set[str] = set()

    def walk(name: str, depth: int) -> None:
        if depth > max_depth:
            return
        if name in seen_sets:
            return
        seen_sets.add(name)

        txt = radb_whois_query(name)
        for token in _radb_extract_members(txt):
            t = token.strip().upper()
            if not t:
                continue
            if re.fullmatch(r"AS\d+", t):
                out_asns.add(t)
                continue
            if t.startswith("AS-") or t.startswith("RS-"):
                walk(t, depth + 1)

    walk(root, 0)
    return out_asns


def transform_hackertarget(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform HackerTarget ASN lookup response into IP ranges."""
    urls = [getattr(r, "url", "unknown") for r in response]
    result = cipr._transform_base(source_key, urls)
    result["method"] = "asn_lookup"
    result["coverage_notes"] = "ASN lookup via HackerTarget (may include non-egress IPs)"

    for r in response:
        lines = r.text.strip().splitlines()
        for line in lines:
            # Expect format: "AS,IP" or "1, 8.8.8.0/24" or new format: "AS","INFO" then IP lines
            line = line.strip()
            if not line or line.startswith("AS,IP"):
                continue

            # Skip quoted ASN info lines (new format)
            if line.startswith('"') and '"' in line and "," in line:
                continue

            parts = line.split(",")
            if len(parts) >= 2:
                ip = parts[1].strip()
                if validate_ip(ip):
                    if ":" in ip:
                        result["ipv6"].append(ip)
                    else:
                        result["ipv4"].append(ip)
                else:
                    logging.warning("Invalid IP range from HackerTarget for %s: %s", source_key, ip)
            elif "/" in line and validate_ip(line):
                # Handle case where line is just an IP range (new format)
                if ":" in line:
                    result["ipv6"].append(line)
                else:
                    result["ipv4"].append(line)

    return result


def transform_ripestat(cipr: Any, response: List[Any], source_key: str) -> Dict[str, Any]:
    """Transform RIPEstat Announced Prefixes response into IP ranges."""
    urls = [getattr(r, "url", "unknown") for r in response]
    result = cipr._transform_base(source_key, urls)
    result["method"] = "bgp_announced"
    result["coverage_notes"] = "BGP-announced prefixes for the ASN"

    for r in response:
        try:
            data = r.json()
            # Set source_updated_at from the first successful response
            if result.get("source_updated_at") is None:
                result["source_updated_at"] = data.get("data", {}).get("queried_at")
            prefixes = data.get("data", {}).get("prefixes", [])
            for entry in prefixes:
                prefix = entry.get("prefix")
                if prefix and validate_ip(prefix):
                    if ":" in prefix:
                        result["ipv6"].append(prefix)
                    else:
                        result["ipv4"].append(prefix)
                elif prefix:
                    logging.warning("Invalid IP range from RIPEstat for %s: %s", source_key, prefix)
        except Exception as e:
            logging.error("Failed to parse RIPEstat response for %s: %s", source_key, e)

    return result


def fetch_and_save_asn_source(cipr: Any, source_key: str, url: List[str]) -> Dict[str, Any]:
    """Fetch and save ASN-based source (direct ASN or RADB AS-SET)."""
    transformed_data = cipr._transform_base(source_key, url)
    transformed_data["method"] = "bgp_announced"
    transformed_data["coverage_notes"] = "BGP-announced prefixes for the ASN(s)"

    source_http: List[Dict[str, Any]] = []
    asns: List[str]
    radb_seed: str | None = None

    if url[0].startswith("RADB::"):
        radb_seed = url[0].split("::", 1)[1].strip()
        resolved = sorted(radb_resolve_as_set(radb_seed))
        if not resolved:
            raise RuntimeError(f"RADB AS-SET {radb_seed} resolved to no ASNs")
        asns = resolved
    else:
        asns = [x for x in url if isinstance(x, str) and x.startswith("AS")]
        if not asns:
            raise RuntimeError(f"ASN source for {source_key} has no ASNs")

    source_list: List[str] = []
    if radb_seed is not None:
        source_list.append(f"RADB::{radb_seed}")

    used_hackertarget = False
    for asn in asns:
        try:
            ripestat_url, r = cipr.ripestat_fetch(asn)
            source_http.append({
                "url": ripestat_url,
                "status": r.status_code,
                "content_type": r.headers.get("content-type"),
                "etag": r.headers.get("etag"),
                "last_modified": r.headers.get("last-modified"),
            })
            tmp = transform_ripestat(cipr, [r], source_key)
            if transformed_data.get("source_updated_at") is None:
                transformed_data["source_updated_at"] = tmp.get("source_updated_at")
            transformed_data["ipv4"].extend(tmp.get("ipv4", []))
            transformed_data["ipv6"].extend(tmp.get("ipv6", []))
            source_list.append(ripestat_url)
        except Exception as e:
            logging.warning("RIPEstat lookup failed for %s %s (%s), falling back to HackerTarget", source_key, asn, str(e))
            used_hackertarget = True
            ht_url = f"https://api.hackertarget.com/aslookup/?q={asn}"
            r = cipr.session.get(ht_url, timeout=10)
            r.raise_for_status()
            source_http.append({
                "url": ht_url,
                "status": r.status_code,
                "content_type": r.headers.get("content-type"),
                "etag": r.headers.get("etag"),
                "last_modified": r.headers.get("last-modified"),
            })
            tmp = transform_hackertarget(cipr, [r], source_key)
            transformed_data["ipv4"].extend(tmp.get("ipv4", []))
            transformed_data["ipv6"].extend(tmp.get("ipv6", []))
            source_list.append(ht_url)

    if used_hackertarget:
        transformed_data["method"] = "asn_lookup"

    transformed_data["source"] = source_list
    transformed_data = cipr._normalize_transformed_data(transformed_data, source_key)
    transformed_data["source_http"] = source_http

    return transformed_data
