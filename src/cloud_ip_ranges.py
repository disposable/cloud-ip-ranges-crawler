import argparse
import csv
import ipaddress
import json
import logging
import os
import re
import sys
import xml.etree.ElementTree as std_ET  # nosec: B405
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.transforms import get_transform


def validate_ip(ip: str) -> Optional[str]:
    """Validate an IP address or subnet."""
    try:
        network = ipaddress.ip_network(ip, strict=False)

        if network.is_private or network.is_loopback or network.is_link_local or network.is_multicast:
            return None

        return ip
    except ValueError as e:
        logging.warning("Invalid IP address/subnet: %s - %s", ip, str(e))
        return None


class CloudIPRanges:
    sources = {
        "aws": ["https://ip-ranges.amazonaws.com/ip-ranges.json"],
        "cloudflare": ["https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"],
        "digitalocean": ["https://digitalocean.com/geo/google.csv"],
        "google_cloud": ["https://www.gstatic.com/ipranges/cloud.json"],
        "google_bot": ["https://developers.google.com/static/search/apis/ipranges/googlebot.json"],
        "bing_bot": ["https://www.bing.com/toolbox/bingbot.json"],
        "oracle_cloud": ["https://docs.oracle.com/iaas/tools/public_ip_ranges.json"],
        "ahrefs": ["https://api.ahrefs.com/v3/public/crawler-ips"],
        "linode": ["https://geoip.linode.com/"],
        "vultr": ["https://geofeed.constant.com/?json"],
        "openai": ["https://openai.com/chatgpt-user.json", "https://openai.com/gptbot.json"],
        "perplexity": ["https://www.perplexity.ai/perplexitybot.json", "https://www.perplexity.ai/perplexity-user.json"],
        "github": ["https://api.github.com/meta"],
        "apple_private_relay": ["https://mask-api.icloud.com/egress-ip-ranges.csv"],
        "starlink": ["https://geoip.starlinkisp.net/feed.csv"],
        "akamai": ["https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_ipv6_CIDRs-txt.zip"],
        "telegram": ["https://core.telegram.org/resources/cidr.txt"],
        "atlassian": ["https://ip-ranges.atlassian.com/"],
        "datadog": ["https://ip-ranges.datadoghq.com/"],
        "okta": ["https://s3.amazonaws.com/okta-ip-ranges/ip_ranges.json"],
        "zendesk": ["https://support.zendesk.com/ips"],
        "vercel": ["76.76.21.0/24", "198.169.1.0/24", "155.121.0.0/16"],
        # "whatsapp": ["https://developers.facebook.com/docs/whatsapp/guides/network-requirements/"],  # Temporarily disabled due to page structure changes
        "zscaler": [
            "https://config.zscaler.com/api/zscaler.net/hubs/cidr/json/required",
            "https://config.zscaler.com/api/zscaler.net/hubs/cidr/json/recommended",
        ],
        "fastly": ["https://api.fastly.com/public-ip-list"],
        "microsoft_azure": ["https://azservicetags.azurewebsites.net/"],
        "softlayer_ibm": ["AS36351"],
        "heroku_aws": ["AS14618"],
        "flyio": ["AS40509"],
        "render": ["AS397273"],
        "a2hosting": ["AS55293"],
        "godaddy": ["AS26496", "AS30083"],
        "dreamhost": ["AS26347"],
        "alibaba": ["AS45102", "AS134963"],
        "tencent": ["AS45090", "AS133478", "AS132591", "AS132203"],
        "ucloud": ["AS135377", "AS59077"],
        "meta_crawler": ["AS32934"],
        "huawei_cloud": ["AS136907", "AS55990"],
        "hetzner": ["AS24940", "AS37153"],
        "choopa": ["AS46407", "AS20473", "AS133795", "AS11508"],
        "ovh": ["AS35540", "AS16276"],
        "onlinesas": ["AS12876"],
        "rackspace": [
            "AS58683",
            "AS54636",
            "AS45187",
            "AS39921",
            "AS36248",
            "AS27357",
            "AS22720",
            "AS19994",
            "AS15395",
            "AS12200",
            "AS10532",
        ],
        "nforce": ["AS64437", "AS43350"],
    }

    # Providers categorized as misc (user ISP traffic, not harmful crawlers)
    misc_providers = {
        "starlink",
    }

    def __init__(self, output_formats: Set[str], only_if_changed: bool = False, max_delta_ratio: Optional[float] = None) -> None:
        self.base_url = Path.cwd()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "cloud-ip-ranges-crawler/1.0 (+https://github.com/disposable/cloud-ip-ranges)",
            "Accept": "application/json, text/plain, */*",
        })

        retry = Retry(
            total=5,
            connect=5,
            read=5,
            status=5,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("HEAD", "GET", "OPTIONS"),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.only_if_changed = only_if_changed
        self.max_delta_ratio = max_delta_ratio
        self.output_formats = output_formats

    def _transform_base(self, source_key: str, source_url: Optional[Union[str, list]] = None) -> Dict[str, Any]:
        """Base transformation method for all providers."""
        if source_url is None:
            source_url = self.sources[source_key]

        generated_at = datetime.now().isoformat()
        result = {
            "provider": source_key.replace("_", " ").title(),
            "provider_id": source_key.replace("_", "-"),
            "method": "published_list",
            "coverage_notes": "",
            "generated_at": generated_at,
            "source_updated_at": None,
            "source": source_url,
            "last_update": generated_at,
            "ipv4": [],
            "ipv6": [],
        }

        if isinstance(source_url, list) and source_url and isinstance(source_url[0], str) and source_url[0].startswith("AS"):
            result["method"] = "asn_lookup"
        return result

    def _extract_cidrs_from_json(self, obj: Any) -> List[str]:
        """Best-effort extraction of CIDR strings from nested JSON-like structures."""
        cidrs: List[str] = []
        cidr_re = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b|\b[0-9a-fA-F:]+/\d{1,3}\b")

        def walk(v: Any, key_hint: str = "") -> None:
            if isinstance(v, str):
                if key_hint and not re.search(r"ip|cidr|prefix|range", key_hint, re.IGNORECASE):
                    return
                for m in cidr_re.findall(v):
                    cidrs.append(m)
                return
            if isinstance(v, list):
                for it in v:
                    walk(it, key_hint)
                return
            if isinstance(v, dict):
                for k, it in v.items():
                    walk(it, str(k))
                return

        walk(obj, "")
        return cidrs

    def _normalize_transformed_data(self, transformed_data: Dict[str, Any], source_key: str) -> Dict[str, Any]:
        ipv4 = set()
        ipv6 = set()
        details_ipv4 = []
        details_ipv6 = []

        for ip in transformed_data["ipv4"]:
            validated_ip = validate_ip(ip)
            if validated_ip:
                ipv4.add(validated_ip)

        # Preserve details if present and valid
        for d in transformed_data.get("details_ipv4", []):
            ip = d.get("address")
            if not ip:
                continue
            validated_ip = validate_ip(ip)
            if validated_ip:
                nd = d.copy()
                nd["address"] = validated_ip
                details_ipv4.append(nd)

        for ip in transformed_data["ipv6"]:
            validated_ip = validate_ip(ip)
            if validated_ip:
                ipv6.add(validated_ip)

        for d in transformed_data.get("details_ipv6", []):
            ip = d.get("address")
            if not ip:
                continue
            validated_ip = validate_ip(ip)
            if validated_ip:
                nd = d.copy()
                nd["address"] = validated_ip
                details_ipv6.append(nd)

        if not ipv4 and not ipv6:
            raise RuntimeError(f"Failed to parse {source_key}")

        transformed_data["ipv4"] = sorted(ipv4)
        transformed_data["ipv6"] = sorted(ipv6)
        if details_ipv4:
            transformed_data["details_ipv4"] = details_ipv4
        if details_ipv6:
            transformed_data["details_ipv6"] = details_ipv6

        return transformed_data

    def _transform_ripestat_announced_prefixes(self, response: List[requests.Response], source_key: str, asn: str) -> Dict[str, Any]:
        """Transform RIPEstat Announced Prefixes response to unified format."""
        ripestat_url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
        result = self._transform_base(source_key, [ripestat_url])
        result["method"] = "bgp_announced"
        result["coverage_notes"] = "BGP-announced prefixes for the ASN"

        data = response[0].json()
        status = data.get("status")
        if status != "ok":
            raise RuntimeError(f"RIPEstat announced-prefixes failed for {asn}: status={status}")

        payload = data.get("data", {})
        result["source_updated_at"] = payload.get("queried_at")

        prefixes = payload.get("prefixes", [])
        if not isinstance(prefixes, list):
            raise RuntimeError("RIPEstat announced-prefixes: invalid prefixes")

        for p in prefixes:
            if not isinstance(p, dict):
                continue
            prefix = p.get("prefix")
            if not prefix:
                continue
            if ":" in prefix:
                result["ipv6"].append(prefix)
            else:
                result["ipv4"].append(prefix)

        return result

    def _transform_hackertarget(self, response: List[requests.Response], source_key: str) -> Dict[str, Any]:
        """Transform HackerTarget AS lookup response to unified format."""

        sources = []
        for s in self.sources[source_key]:
            sources.append(s.replace("", ""))

        result = self._transform_base(source_key, ", ".join(sources))
        result["method"] = "asn_lookup"
        data = response[0].text
        if "API count exceeded" in data:
            raise RuntimeError("API request count exceeded")

        for x, line in enumerate(data.split("\n")):
            if not line.strip() or line.startswith("#") or x == 0:
                continue
            ip = line.strip().split()[-1]
            if ":" in ip:
                result["ipv6"].append(ip)
            else:
                result["ipv4"].append(ip)

        return result

    def _xml_find_text(self, root: std_ET.Element, tag_local: str) -> Optional[str]:  # type: ignore
        for el in root.iter():
            if el.tag.endswith("}" + tag_local) and el.text:  # type: ignore
                return el.text
        return None

    def _transform_response(self, response: List[requests.Response], source_key: str, is_asn: bool) -> Dict[str, Any]:
        if is_asn:
            transformed_data = self._transform_hackertarget(response, source_key)
        else:
            transform_fn = get_transform(source_key)
            transformed_data = transform_fn(self, response, source_key)

        return self._normalize_transformed_data(transformed_data, source_key)

    def _fetch_and_save(self, source_key: str) -> Optional[tuple[int, int]]:
        """Fetch and save IP ranges for a specific source."""
        logging.debug("Fetching %s source", source_key)
        url = self.sources[source_key]

        transformed_data: Dict[str, Any]
        source_http: List[Dict[str, Any]] = []

        def is_seed_cidr(v: str) -> bool:
            if v.startswith("http://") or v.startswith("https://"):
                return False
            if "/" not in v:
                return False
            try:
                ipaddress.ip_network(v, strict=False)
                return True
            except Exception:
                return False

        if isinstance(url, list) and url and isinstance(url[0], str) and is_seed_cidr(url[0]):
            # Seed CIDR sources: each seed gets its own RDAP lookup
            response = []
            for seed in url:
                seed_ip = seed.split("/")[0]
                rdap_url = f"https://rdap.arin.net/registry/ip/{seed_ip}"
                r = self.session.get(rdap_url, timeout=10)
                r.raise_for_status()
                response.append(r)
                source_http.append({
                    "url": rdap_url,
                    "status": r.status_code,
                    "content_type": r.headers.get("content-type"),
                    "etag": r.headers.get("etag"),
                    "last_modified": r.headers.get("last-modified"),
                })
            transformed_data = self._transform_response(response, source_key, is_asn=False)
        elif url and isinstance(url[0], str) and url[0].startswith("AS"):
            asn = url[0]
            ripestat_url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
            try:
                r = self.session.get(ripestat_url, timeout=10)
                r.raise_for_status()
                source_http.append({
                    "url": ripestat_url,
                    "status": r.status_code,
                    "content_type": r.headers.get("content-type"),
                    "etag": r.headers.get("etag"),
                    "last_modified": r.headers.get("last-modified"),
                })
                transformed_data = self._transform_ripestat_announced_prefixes([r], source_key, asn)
                transformed_data = self._normalize_transformed_data(transformed_data, source_key)
            except Exception as e:
                logging.warning("RIPEstat lookup failed for %s (%s), falling back to HackerTarget", source_key, str(e))
                response = []
                for u in url:
                    if u.startswith("AS"):
                        u = f"https://api.hackertarget.com/aslookup/?q={u}"
                    r = self.session.get(u, timeout=10)
                    r.raise_for_status()
                    response.append(r)
                    source_http.append({
                        "url": u,
                        "status": r.status_code,
                        "content_type": r.headers.get("content-type"),
                        "etag": r.headers.get("etag"),
                        "last_modified": r.headers.get("last-modified"),
                    })
                transformed_data = self._transform_response(response, source_key, is_asn=True)
        else:
            response = []
            for u in url:
                r = self.session.get(u, timeout=10)
                r.raise_for_status()
                response.append(r)
                source_http.append({
                    "url": u,
                    "status": r.status_code,
                    "content_type": r.headers.get("content-type"),
                    "etag": r.headers.get("etag"),
                    "last_modified": r.headers.get("last-modified"),
                })
            transformed_data = self._transform_response(response, source_key, is_asn=False)

        if source_http:
            transformed_data["source_http"] = source_http

        # Always perform basic safety audit
        self._audit_transformed_data(transformed_data, source_key)

        json_filename = "{}.json".format(source_key.replace("_", "-"))
        json_path = self.base_url / json_filename
        existing_data_raw: Optional[Dict[str, Any]] = None

        if json_path.exists():
            with open(json_path, "r") as f:
                existing_data_raw = json.load(f)

        if existing_data_raw is not None:
            if self.max_delta_ratio is not None:
                self._enforce_max_delta(existing_data_raw, transformed_data, max_ratio=self.max_delta_ratio, source_key=source_key)
                logging.debug("Delta summary for %s: %s", source_key, json.dumps(self._diff_summary(existing_data_raw, transformed_data)))

            if self.only_if_changed:
                existing_data = existing_data_raw.copy()
                existing_data.pop("last_update", None)
                existing_data.pop("generated_at", None)
                existing_data.pop("source_http", None)
                new_data = transformed_data.copy()
                new_data.pop("last_update", None)
                new_data.pop("generated_at", None)
                new_data.pop("source_http", None)

                if existing_data == new_data:
                    logging.debug("No changes found for %s, skipping other formats", source_key)
                    # Still return statistics even when no changes
                    return len(transformed_data["ipv4"]), len(transformed_data["ipv6"])

        return self._save_result(transformed_data, source_key)

    def _audit_transformed_data(self, transformed_data: Dict[str, Any], source_key: str) -> None:
        """Raise on obviously dangerous/broken outputs."""
        invalid = []
        for ip in transformed_data.get("ipv4", []):
            if ip in ("0.0.0.0/0", "0.0.0.0"):  # default route  # nosec: B104
                invalid.append(ip)
        for ip in transformed_data.get("ipv6", []):
            if ip in ("::/0", "::"):
                invalid.append(ip)

        if invalid:
            raise RuntimeError(f"Audit failed for {source_key}: contains default route(s): {', '.join(invalid)}")

    def _diff_summary(self, old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
        old4 = set(old.get("ipv4", []) or [])
        old6 = set(old.get("ipv6", []) or [])
        new4 = set(new.get("ipv4", []) or [])
        new6 = set(new.get("ipv6", []) or [])
        return {
            "ipv4": {"old": len(old4), "new": len(new4), "added": len(new4 - old4), "removed": len(old4 - new4)},
            "ipv6": {"old": len(old6), "new": len(new6), "added": len(new6 - old6), "removed": len(old6 - new6)},
        }

    def _enforce_max_delta(self, old: Dict[str, Any], new: Dict[str, Any], *, max_ratio: float, source_key: str) -> None:
        def ratio(old_n: int, new_n: int) -> float:
            if old_n == 0:
                return float("inf") if new_n > 0 else 0.0
            return abs(new_n - old_n) / float(old_n)

        s = self._diff_summary(old, new)
        r4 = ratio(s["ipv4"]["old"], s["ipv4"]["new"])
        r6 = ratio(s["ipv6"]["old"], s["ipv6"]["new"])

        if (r4 != float("inf") and r4 > max_ratio) or (r6 != float("inf") and r6 > max_ratio):
            raise RuntimeError(f"Delta check failed for {source_key}: {json.dumps(s)}")

    def _save_json(self, transformed_data: Dict[str, Any], filename: str) -> None:
        """Save data in JSON format."""
        with open(self.base_url / filename, "w") as f:
            json.dump(transformed_data, f, indent=2)

    def _save_csv(self, transformed_data: Dict[str, Any], filename: str) -> None:
        """Save data in CSV format."""
        with open(self.base_url / filename, "w") as f:
            writer = csv.writer(f)
            writer.writerow(["Type", "Address"])
            for ip in transformed_data["ipv4"]:
                writer.writerow(["IPv4", ip])
            for ip in transformed_data["ipv6"]:
                writer.writerow(["IPv6", ip])

    def _save_txt(self, transformed_data: Dict[str, Any], filename: str) -> None:
        """Save data in TXT format."""
        with open(self.base_url / filename, "w") as f:
            for k in ("provider", "source", "last_update"):
                vl = ", ".join(transformed_data[k]) if isinstance(transformed_data[k], list) else transformed_data[k]
                f.write("# {}: {}\n".format(k, vl))

            f.write("\n")
            f.write("\n".join(transformed_data["ipv4"]))
            if transformed_data["ipv6"]:
                f.write("\n")
                f.write("\n".join(transformed_data["ipv6"]))

    def _save_details_files(self, transformed_data: Dict[str, Any], base_name: str) -> bool:
        """Save detailed metadata files if available."""
        if not (transformed_data.get("details_ipv4") or transformed_data.get("details_ipv6")):
            return False

        details_written = False

        if "json" in self.output_formats:
            self._save_json_details(transformed_data, base_name)
            details_written = True

        if "csv" in self.output_formats:
            self._save_csv_details(transformed_data, base_name)
            details_written = True

        return details_written

    def _save_json_details(self, transformed_data: Dict[str, Any], base_name: str) -> None:
        """Save detailed metadata in JSON format."""
        details_json_path = self.base_url / f"{base_name}-details.json"
        details_payload = {
            "provider": transformed_data.get("provider"),
            "provider_id": transformed_data.get("provider_id"),
            "method": transformed_data.get("method"),
            "coverage_notes": transformed_data.get("coverage_notes"),
            "generated_at": transformed_data.get("generated_at"),
            "source_updated_at": transformed_data.get("source_updated_at"),
            "source": transformed_data.get("source"),
            "last_update": transformed_data.get("last_update"),
            "ipv4": transformed_data.get("details_ipv4", []),
            "ipv6": transformed_data.get("details_ipv6", []),
        }
        with open(details_json_path, "w") as df:
            json.dump(details_payload, df, indent=2)

    def _save_csv_details(self, transformed_data: Dict[str, Any], base_name: str) -> None:
        """Save detailed metadata in CSV format."""
        details_csv_path = self.base_url / f"{base_name}-details.csv"

        # Collect all metadata keys
        keys: Set[str] = set()
        for d in transformed_data.get("details_ipv4", []):
            keys.update(k for k in d.keys() if k != "address")
        for d in transformed_data.get("details_ipv6", []):
            keys.update(k for k in d.keys() if k != "address")
        ordered_keys = sorted(keys)

        with open(details_csv_path, "w") as df:
            writer = csv.writer(df)
            writer.writerow(["Type", "Address", *ordered_keys])
            for d in transformed_data.get("details_ipv4", []):
                writer.writerow(["IPv4", d.get("address"), *[d.get(k) for k in ordered_keys]])
            for d in transformed_data.get("details_ipv6", []):
                writer.writerow(["IPv6", d.get("address"), *[d.get(k) for k in ordered_keys]])

    def _save_result(self, transformed_data: Dict[str, Any], source_key: str) -> tuple[int, int]:
        """Save transformed data in all configured output formats."""
        # Format writer methods mapping
        format_writers = {
            "json": self._save_json,
            "csv": self._save_csv,
            "txt": self._save_txt,
        }

        base_name = source_key.replace("_", "-")

        # Save main files in each format
        for x, output_format in enumerate(self.output_formats):
            filename = f"{base_name}.{output_format}"

            if output_format not in format_writers:
                raise ValueError(f"Unknown output format: {output_format}")

            format_writers[output_format](transformed_data, filename)

            # Log first format as info, others as debug
            log_message = "Saved %s [IPv4: %d, IPv6: %d]" if x == 0 else "Saved %s"
            log_level = logging.info if x == 0 else logging.debug
            log_level(log_message, filename, len(transformed_data["ipv4"]), len(transformed_data["ipv6"]))

        # Save detailed metadata files if available
        if self._save_details_files(transformed_data, base_name):
            logging.debug("Saved %s-details.(json/csv)", base_name)

        return len(transformed_data["ipv4"]), len(transformed_data["ipv6"])

    def fetch_all(self, sources: Optional[Set[str]] = None) -> bool:
        error = False
        self.statistics = {}
        try:
            for source in self.sources:
                if sources is not None and source not in sources:
                    continue
                try:
                    if res := self._fetch_and_save(source):
                        ipv4_count, ipv6_count = res
                        self.statistics[source] = {"ipv4": ipv4_count, "ipv6": ipv6_count}
                except Exception as e:
                    logging.error("Failed to fetch %s: %s", source, str(e))
                    logging.exception(e)
                    error = True

        except Exception as e:
            logging.error("Error during IP range collection: %s", e)
            raise

        return not error

    def add_env_statistics(self) -> None:
        total_ipv4 = 0
        total_ipv6 = 0
        sources_updated = []

        # Calculate totals
        for source, stats in self.statistics.items():
            total_ipv4 += stats["ipv4"]
            total_ipv6 += stats["ipv6"]
            sources_updated.append(source)

        if github_output := os.getenv("GITHUB_OUTPUT"):
            with open(github_output, "a") as f:
                f.write(f"total_ipv4={total_ipv4}\n")
                f.write(f"total_ipv6={total_ipv6}\n")
                f.write(f"sources_updated={','.join(sources_updated)}\n")
                f.write(f"sources_count={len(sources_updated)}\n")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Collect IP ranges from cloud providers")
    parser.add_argument("--sources", nargs="+", choices=CloudIPRanges.sources.keys(), help="Specific sources to update (e.g., aws google_cloud)")
    parser.add_argument("--only-if-changed", action="store_true", help="Only write files if there are changes (only works with JSON format)")
    parser.add_argument(
        "--max-delta-ratio",
        type=float,
        default=None,
        help="Fail if an existing provider changes by more than this ratio (e.g. 0.3 for 30%%). Only applies when an existing JSON file is present.",
    )
    parser.add_argument("--add-env-statistics", action="store_true", help="Add statistics to environment variables for github action")
    parser.add_argument(
        "--output-format", nargs="+", choices=["json", "csv", "txt"], default=["json"], help="Output format(s) to save the data in (default: json)"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--log-file", type=str, help="Log file")
    parser.add_argument("--misc", action="store_true", help="Only process misc providers (user ISP traffic like Starlink)")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO

    if args.log_file:
        logging.basicConfig(level=log_level, format="%(asctime)s - %(levelname)s - %(message)s", filename=args.log_file)
    else:
        logging.basicConfig(level=log_level, format="%(asctime)s - %(levelname)s - %(message)s")

    # Convert sources to set if specified, otherwise None
    sources = set(args.sources) if args.sources else None
    output_formats = set(args.output_format)
    cloud_ip_ranges = CloudIPRanges(output_formats, args.only_if_changed, max_delta_ratio=args.max_delta_ratio)

    # Handle --misc flag: only process misc providers
    if args.misc:
        if sources is not None:
            # If specific sources requested, filter to only misc providers
            sources = sources.intersection(cloud_ip_ranges.misc_providers)
        else:
            # If no specific sources, use all misc providers
            sources = cloud_ip_ranges.misc_providers
    elif sources is not None:
        # If specific sources requested and not --misc, exclude misc providers
        sources = sources.difference(cloud_ip_ranges.misc_providers)
    else:
        # Default: exclude misc providers
        sources = set(cloud_ip_ranges.sources.keys()).difference(cloud_ip_ranges.misc_providers)

    if not cloud_ip_ranges.fetch_all(sources):
        sys.exit(1)

    if args.add_env_statistics:
        cloud_ip_ranges.add_env_statistics()


if __name__ == "__main__":
    main()
