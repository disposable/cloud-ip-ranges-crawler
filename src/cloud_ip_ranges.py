import argparse
import csv
import ipaddress
import json
import logging
import os
import re
import sys
import time
import xml.etree.ElementTree as std_ET  # nosec: B405
from datetime import datetime
from operator import attrgetter
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Ensure the src directory (containing this module and its siblings) is importable when run as a script
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

import requests
from cachetools import LRUCache, cachedmethod
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from sources.asn import fetch_and_save_asn_source
from sources.http import fetch_and_save_http_source
from sources.seed_cidr import fetch_and_save_seed_cidr_source
from transforms.common import validate_ip
from ip_merger import IPMerger


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
        "circleci": ["https://circleci.com/docs/ip-ranges-list.json"],
        "hcp_terraform": ["https://app.terraform.io/api/meta/ip-ranges"],
        "new_relic_synthetics": ["https://nr-synthetics-assets.s3.amazonaws.com/nat-ip-dnsname/production/ip-ranges.json"],
        "grafana_cloud": [
            "https://grafana.com/api/hosted-alerts/source-ips",
            "https://grafana.com/api/hosted-grafana/source-ips",
            "https://grafana.com/api/hosted-metrics/source-ips",
            "https://grafana.com/api/hosted-traces/source-ips",
            "https://grafana.com/api/hosted-logs/source-ips",
            "https://grafana.com/api/hosted-profiles/source-ips",
            "https://grafana.com/api/hosted-otlp/source-ips",
        ],
        "intercom": [
            "https://static.intercomcdn.com/intercom-ips/us/intercom-ip-ranges.json",
            "https://static.intercomcdn.com/intercom-ips/eu/intercom-ip-ranges.json",
            "https://static.intercomcdn.com/intercom-ips/au/intercom-ip-ranges.json",
        ],
        "stripe": ["https://stripe.com/files/ips/ips_api.json", "https://stripe.com/files/ips/ips_webhooks.json"],
        "adyen": ["https://docs.adyen.com/development-resources/security/integration-security/allowlisting"],
        "salesforce_hyperforce": ["https://ip-ranges.salesforce.com/ip-ranges.json"],
        "sentry": ["https://sentry.io/api/0/uptime-ips/"],
        "branch": ["https://help.branch.io/docs/postback-webhook-ip-address-allowlist-expands"],
        "vercel": ["76.76.21.0/24", "198.169.1.0/24", "155.121.0.0/16"],
        "zscaler": [
            "https://config.zscaler.com/api/zscaler.net/hubs/cidr/json/required",
            "https://config.zscaler.com/api/zscaler.net/hubs/cidr/json/recommended",
        ],
        "fastly": ["https://api.fastly.com/public-ip-list"],
        "microsoft_azure": ["https://azservicetags.azurewebsites.net/"],
        "exoscale": ["https://exoscale-prefixes.sos-ch-dk-2.exo.io/exoscale_prefixes.json"],
        "scaleway": ["https://www.scaleway.com/en/docs/account/reference-content/scaleway-network-information/"],
        "backblaze": ["https://www.backblaze.com/computer-backup/docs/backblaze-ip-addresses"],
        "cisco_webex": [
            "https://help.webex.com/article/WBX000028782/Network-Requirements-for-Webex-Teams-Services",
            "https://help.webex.com/en-us/article/WBX264/How-Do-I-Allow-Webex-Meetings-Traffic-on-My-Network",
        ],
        "softlayer_ibm": ["RADB::AS-SOFTLAYER"],
        "heroku_aws": ["AS14618"],
        "flyio": ["AS40509"],
        "render": ["AS397273"],
        "a2hosting": ["AS55293"],
        "godaddy": ["AS26496", "AS30083"],
        "dreamhost": ["AS26347"],
        "alibaba": ["RADB::AS-ALIBABA-CN-NET", "AS134963"],
        "tencent": ["RADB::AS132203:AS-TENCENT"],
        "ucloud": ["AS135377", "AS59077"],
        "meta_crawler": ["RADB::AS-FACEBOOK"],
        "huawei_cloud": ["RADB::AS-HUAWEI"],
        "hetzner": ["RADB::AS-HETZNER"],
        "choopa": ["AS46407", "AS20473", "AS133795", "AS11508"],
        "ovh": ["RADB::AS-OVH"],
        "onlinesas": ["RADB::AS-ONLINESAS"],
        "rackspace": ["RADB::AS-RACKSPACE"],
        "nforce": ["RADB::AS-NFORCE"],
        "upcloud": ["AS202053", "AS25697"],
        "gridscale": ["AS29423"],
        "aruba_cloud": ["AS200185"],
        "ionos_cloud": ["AS8560"],
        "cyso_cloud": ["AS25151"],
        "seeweb": ["AS12637"],
        "open_telekom_cloud": ["AS6878"],
        "wasabi": ["AS395717"],
        "kamatera": ["AS36007"],
    }

    # Providers categorized as misc (user ISP traffic, not harmful crawlers)
    misc_providers = {
        "starlink",
    }

    def __init__(
        self,
        output_formats: Set[str],
        only_if_changed: bool = False,
        max_delta_ratio: Optional[float] = None,
        output_dir: Optional[Path] = None,
        merge_all_providers: bool = False,
    ) -> None:
        self.base_url = Path(output_dir).expanduser() if output_dir else Path.cwd()
        self.base_url.mkdir(parents=True, exist_ok=True)
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
        self.merge_all_providers = merge_all_providers
        self.ip_merger = IPMerger()
        self._sources_with_changes: Set[str] = set()
        cache_size = int(os.getenv("RIPESTAT_CACHE_SIZE", "1024"))
        self._ripestat_cache: LRUCache[str, Tuple[str, requests.Response]] = LRUCache(maxsize=max(cache_size, 1))
        self._ripestat_last_request = 0.0
        # Allow overriding via env (seconds between RIPEstat calls)
        self._ripestat_min_interval = float(os.getenv("RIPESTAT_MIN_INTERVAL", "0.1"))

    def ripestat_fetch(self, asn: str) -> Tuple[str, requests.Response]:
        """Fetch RIPEstat announced prefixes for an ASN with caching/rate limiting."""
        cache_key = asn.strip().upper()
        if not cache_key.startswith("AS"):
            raise ValueError(f"Invalid ASN: {asn}")

        return self._ripestat_fetch_uncached(cache_key)

    @cachedmethod(cache=attrgetter("_ripestat_cache"))
    def _ripestat_fetch_uncached(self, cache_key: str) -> Tuple[str, requests.Response]:
        now = time.monotonic()
        elapsed = now - self._ripestat_last_request
        if elapsed < self._ripestat_min_interval:
            sleep_time = self._ripestat_min_interval - elapsed
            logging.debug("Sleeping %.2fs before RIPEstat request", sleep_time)
            time.sleep(sleep_time)

        ripestat_url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={cache_key}"
        response = self.session.get(ripestat_url, timeout=10)
        response.raise_for_status()
        self._ripestat_last_request = time.monotonic()
        return ripestat_url, response

    def _comparable_payload(self, data: Dict[str, Any]) -> Dict[str, Any]:
        comparable = data.copy()
        for key in ("last_update", "generated_at", "source_http"):
            comparable.pop(key, None)
        return comparable

    def _save_merged_outputs(self) -> None:
        if not self.merge_all_providers or not self.ip_merger.has_data:
            return

        merged_payload = self.ip_merger.get_merged_output()

        if "json" in self.output_formats:
            with open(self.base_url / "all-providers.json", "w") as f:
                json.dump(merged_payload, f, indent=2)

        if "csv" in self.output_formats:
            with open(self.base_url / "all-providers.csv", "w") as f:
                writer = csv.writer(f)
                writer.writerow(["Type", "Address", "Providers"])
                for ip in merged_payload.get("ipv4", []):
                    providers = ";".join(merged_payload["ip_providers"].get(ip, []))
                    writer.writerow(["IPv4", ip, providers])
                for ip in merged_payload.get("ipv6", []):
                    providers = ";".join(merged_payload["ip_providers"].get(ip, []))
                    writer.writerow(["IPv6", ip, providers])

        if "txt" in self.output_formats:
            provider_ids = ", ".join(filter(None, (p.get("provider_id") for p in merged_payload.get("providers", []))))
            with open(self.base_url / "all-providers.txt", "w") as f:
                f.write("# provider: All Providers\n")
                f.write(f"# providers_count: {merged_payload.get('provider_count', 0)}\n")
                f.write(f"# provider_ids: {provider_ids}\n")
                f.write(f"# generated_at: {merged_payload.get('generated_at')}\n")

                addresses: List[str] = []
                addresses.extend(merged_payload.get("ipv4", []))
                addresses.extend(merged_payload.get("ipv6", []))
                if addresses:
                    f.write("\n")
                    f.write("\n".join(addresses))

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

        if (
            isinstance(source_url, list)
            and source_url
            and isinstance(source_url[0], str)
            and (source_url[0].startswith("AS") or source_url[0].startswith("RADB::"))
        ):
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
        # Preserve important metadata fields
        preserved_fields = {}
        for field in ["method", "coverage_notes", "source_updated_at", "source"]:
            if field in transformed_data:
                preserved_fields[field] = transformed_data[field]

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

        # Restore preserved fields
        transformed_data.update(preserved_fields)

        return transformed_data

    def _xml_find_text(self, root: std_ET.Element, tag_local: str) -> Optional[str]:  # type: ignore
        for el in root.iter():
            if el.tag.endswith("}" + tag_local) and el.text:  # type: ignore
                return el.text
        return None

    def _fetch_and_save(self, source_key: str) -> Optional[tuple[int, int]]:
        """Fetch and save IP ranges for a specific source."""
        logging.debug("Fetching %s source", source_key)
        url = self.sources[source_key]

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

        # Route to appropriate source handler
        if isinstance(url, list) and url and isinstance(url[0], str) and is_seed_cidr(url[0]):
            transformed_data = fetch_and_save_seed_cidr_source(self, source_key, url)
        elif isinstance(url, list) and url and isinstance(url[0], str) and (url[0].startswith("AS") or url[0].startswith("RADB::")):
            transformed_data = fetch_and_save_asn_source(self, source_key, url)
        else:
            transformed_data = fetch_and_save_http_source(self, source_key, url)

        # Always perform basic safety audit
        self._audit_transformed_data(transformed_data, source_key)

        json_filename = "{}.json".format(source_key.replace("_", "-"))
        json_path = self.base_url / json_filename
        existing_data_raw: Optional[Dict[str, Any]] = None
        data_changed = True

        if json_path.exists():
            with open(json_path, "r") as f:
                existing_data_raw = json.load(f)

        if existing_data_raw is not None:
            if self.max_delta_ratio is not None:
                self._enforce_max_delta(existing_data_raw, transformed_data, max_ratio=self.max_delta_ratio, source_key=source_key)
                logging.debug("Delta summary for %s: %s", source_key, json.dumps(self._diff_summary(existing_data_raw, transformed_data)))

            comparable_existing = self._comparable_payload(existing_data_raw)
            comparable_new = self._comparable_payload(transformed_data)
            data_changed = comparable_existing != comparable_new

            if self.only_if_changed and not data_changed:
                logging.debug("No changes found for %s, skipping other formats", source_key)
                # Still return statistics even when no changes
                if self.merge_all_providers:
                    self.ip_merger.add_provider_data(transformed_data)
                return len(transformed_data["ipv4"]), len(transformed_data["ipv6"])

        counts = self._save_result(transformed_data, source_key)
        if data_changed:
            self._sources_with_changes.add(source_key)
        if self.merge_all_providers:
            self.ip_merger.add_provider_data(transformed_data)
        return counts

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
            if x == 0:
                logging.info("Saved %s [IPv4: %d, IPv6: %d]", filename, len(transformed_data["ipv4"]), len(transformed_data["ipv6"]))
            else:
                logging.debug("Saved %s", filename)

        # Save detailed metadata files if available
        if self._save_details_files(transformed_data, base_name):
            logging.debug("Saved %s-details.(json/csv)", base_name)

        return len(transformed_data["ipv4"]), len(transformed_data["ipv6"])

    def fetch_all(self, sources: Optional[Set[str]] = None) -> bool:
        error = False
        self.statistics = {}
        self._sources_with_changes = set()
        if self.merge_all_providers:
            self.ip_merger.reset()
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
        finally:
            if self.merge_all_providers:
                self._save_merged_outputs()

        return not error

    def add_env_statistics(self) -> None:
        total_ipv4 = 0
        total_ipv6 = 0

        # Calculate totals
        for stats in self.statistics.values():
            total_ipv4 += stats["ipv4"]
            total_ipv6 += stats["ipv6"]

        if github_output := os.getenv("GITHUB_OUTPUT"):
            with open(github_output, "a") as f:
                f.write(f"total_ipv4={total_ipv4}\n")
                f.write(f"total_ipv6={total_ipv6}\n")
                f.write(f"sources_updated={','.join(sorted(self._sources_with_changes))}\n")
                f.write(f"sources_count={len(self._sources_with_changes)}\n")


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
    parser.add_argument(
        "--output-dir",
        type=str,
        help="Directory where generated files will be written (defaults to the current working directory)",
    )
    parser.add_argument(
        "--merge-all-providers",
        action="store_true",
        help="Generate consolidated all-providers files (disabled by default)",
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
    output_dir = Path(args.output_dir).expanduser() if args.output_dir else Path.cwd()
    output_dir.mkdir(parents=True, exist_ok=True)
    cloud_ip_ranges = CloudIPRanges(
        output_formats,
        args.only_if_changed,
        max_delta_ratio=args.max_delta_ratio,
        output_dir=output_dir,
        merge_all_providers=args.merge_all_providers,
    )

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
