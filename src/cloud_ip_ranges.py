import argparse
import csv
import html
import io
import ipaddress
import json
import logging
import re
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


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
        "apple_icloud": ["https://mask-api.icloud.com/egress-ip-ranges.csv"],
        "starlink": ["https://geoip.starlinkisp.net/feed.csv"],
        "akamai": ["https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_ipv6_CIDRs-txt.zip"],
        "telegram": ["https://core.telegram.org/resources/cidr.txt"],
        "whatsapp": ["https://developers.facebook.com/docs/whatsapp/guides/network-requirements/"],
        "zscaler": [
            "https://config.zscaler.com/api/zscaler.net/hubs/cidr/json/required",
            "https://config.zscaler.com/api/zscaler.net/hubs/cidr/json/recommended",
        ],
        "fastly": ["https://api.fastly.com/public-ip-list"],
        "microsoft_azure": ["https://azservicetags.azurewebsites.net/"],
        "softlayer_ibm": ["AS36351"],
        "vercel_aws": ["AS15169"],
        "heroku_aws": ["AS14618"],
        "a2hosting": ["AS55293"],
        "godaddy": ["AS26496", "AS30083"],
        "dreamhost": ["AS26347"],
        "alibaba": ["AS45102", "AS134963"],
        "tencent": ["AS45090", "AS133478", "AS132591", "AS132203"],
        "ucloud": ["AS135377", "AS59077"],
        "meta_crawler": ["AS32934"],
        "huawei_cloud": ["AS136907", "AS55990"],
        "rackspace": ["AS39921", "AS12200", "AS15395", "AS44009", "AS45187", "AS58683", "AS27357", "AS19994"],
        "hetzner": ["AS24940", "AS37153"],
        "choopa": ["AS47540", "AS46407", "AS20473", "AS133795", "AS11508"],
        "ovh": ["AS35540", "AS16276"],
        "onlinesas": ["AS12876"],
        "rackspace": [
            "AS58683",
            "AS54636",
            "AS45187",
            "AS44716",
            "AS39921",
            "AS36248",
            "AS33070",
            "AS27357",
            "AS22720",
            "AS19994",
            "AS15395",
            "AS12200",
            "AS10532",
        ],
        "nforce": ["AS64437", "AS43350"],
    }

    def __init__(self, output_formats: Set[str], only_if_changed: bool = False) -> None:
        self.base_url = Path.cwd()
        self.session = requests.Session()
        self.only_if_changed = only_if_changed
        self.output_formats = output_formats

    def _transform_base(self, source_key: str, source_url: Optional[Union[str, list]] = None) -> Dict[str, Any]:
        """Base transformation method for all providers."""
        if source_url is None:
            source_url = self.sources[source_key]

        result = {"provider": source_key.replace("_", " ").title(), "source": source_url, "last_update": datetime.now().isoformat(), "ipv4": [], "ipv6": []}
        return result

    def _transform_hackertarget(self, response: List[requests.Response], source_key: str) -> Dict[str, Any]:
        """Transform HackerTarget AS lookup response to unified format."""

        sources = []
        for s in self.sources[source_key]:
            sources.append(s.replace("", ""))

        result = self._transform_base(source_key, ", ".join(sources))
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

    def _transform_aws(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform AWS data to unified format."""
        result = self._transform_base("aws")
        data = response[0].json()
        result["last_update"] = data["createDate"]

        if "prefixes" in data:
            for prefix in data["prefixes"]:
                result["ipv4"].append(prefix["ip_prefix"])

        if "ipv6_prefixes" in data:
            for prefix in data["ipv6_prefixes"]:
                result["ipv6"].append(prefix["ipv6_prefix"])

        return result

    def _transform_digitalocean(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform DigitalOcean data to unified format."""
        result = self._transform_base("digitalocean")
        data = response[0].text

        lines = data.splitlines()
        for line in lines:
            if not line.strip():
                continue
            prefix = line.split(",")[0]
            if ":" in prefix:
                result["ipv6"].append(prefix)
            else:
                result["ipv4"].append(prefix)

        return result

    def _transform_cloudflare(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Cloudflare data to unified format."""
        result = self._transform_base("cloudflare")

        data = [r.text for r in response]

        if isinstance(data[0], str):
            result["ipv4"] = data[0].splitlines()

        if isinstance(data[1], str):
            result["ipv6"] = data[1].splitlines()

        return result

    def _transform_csv_format(self, response: List[requests.Response], source_key: str) -> Dict[str, Any]:
        """Transform CSV format data (used by Linode and Apple iCloud) to unified format."""
        result = self._transform_base(source_key)
        data = response[0].text

        lines = data.splitlines()
        for line in lines:
            if not line.strip() or line.startswith("#"):
                continue

            ip = line.split(",")[0]
            if ":" in ip:
                result["ipv6"].append(ip)
            else:
                result["ipv4"].append(ip)

        return result

    def _transform_telegram(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Telegram CIDR ranges to unified format."""
        return self._transform_csv_format(response, "telegram")

    def _transform_linode(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Linode data to unified format."""
        return self._transform_csv_format(response, "linode")

    def _transform_apple_icloud(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Apple iCloud data to unified format."""
        return self._transform_csv_format(response, "apple_icloud")

    def _transform_starlink(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Starlink ISP data to unified format."""
        return self._transform_csv_format(response, "starlink")

    def _transform_zscaler(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Zscaler data to unified format."""
        result = self._transform_base("zscaler")

        # Process required IPs
        required_data = response[0].json()
        if isinstance(required_data, dict) and "hubPrefixes" in required_data:
            for prefix in required_data["hubPrefixes"]:
                if ":" in prefix:
                    result["ipv6"].append(prefix)
                else:
                    result["ipv4"].append(prefix)

        # Process recommended IPs
        recommended_data = response[1].json()
        if isinstance(recommended_data, dict) and "hubPrefixes" in recommended_data:
            for prefix in recommended_data["hubPrefixes"]:
                if ":" in prefix:
                    result["ipv6"].append(prefix)
                else:
                    result["ipv4"].append(prefix)

        return result

    def _transform_google_style(self, response: List[requests.Response], source_key: str) -> Dict[str, Any]:
        """Transform Google-style JSON files (Google Bot, OpenAI, Google Cloud) to unified format."""
        result = self._transform_base(source_key)

        for r in response:
            data = r.json()
            result["last_update"] = data["creationTime"]

            prefixes = data.get("prefixes", [])
            for prefix in prefixes:
                if "ipv4Prefix" in prefix:
                    result["ipv4"].append(prefix["ipv4Prefix"])
                if "ipv6Prefix" in prefix:
                    result["ipv6"].append(prefix["ipv6Prefix"])

        return result

    def _transform_google_bot(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Google Bot IP ranges to unified format."""
        return self._transform_google_style(response, "google_bot")

    def _transform_bing_bot(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Bing Bot IP ranges to unified format."""
        return self._transform_google_style(response, "bing_bot")

    def _transform_google_cloud(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Google Cloud data to unified format."""
        return self._transform_google_style(response, "google_cloud")

    def _transform_openai(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform OpenAI IP ranges to unified format."""
        return self._transform_google_style(response, "openai")

    def _transform_perplexity(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Perplexity IP ranges to unified format."""
        return self._transform_google_style(response, "perplexity")

    def _transform_fastly(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Fastly data to unified format."""
        result = self._transform_base("fastly")
        data = response[0].json()

        if isinstance(data, dict):
            # Add IPv4 addresses
            for ip in data.get("addresses", []):
                result["ipv4"].append(ip)

            # Add IPv6 addresses
            for ip in data.get("ipv6_addresses", []):
                result["ipv6"].append(ip)

        return result

    def _transform_microsoft(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Microsoft data to unified format."""
        result = self._transform_base("microsoft")
        data = response[0].json()

        if isinstance(data, dict) and "value" in data:
            for service in data["value"]:
                if "properties" in service and "addressPrefixes" in service["properties"]:
                    for prefix in service["properties"]["addressPrefixes"]:
                        if ":" in prefix:
                            result["ipv6"].append(prefix)
                        else:
                            result["ipv4"].append(prefix)

        return result

    def _transform_oracle_cloud(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Oracle Cloud data to unified format."""
        result = self._transform_base("oracle_cloud")
        data = response[0].json()

        if isinstance(data, dict):
            regions = data.get("regions", [])
            for region in regions:
                cidrs = region.get("cidrs", [])
                ipv4_cidrs = region.get("ipv4_cidrs", [])
                ipv6_cidrs = region.get("ipv6_cidrs", [])

                for cidr in cidrs:
                    ip = cidr.get("cidr")
                    if ip:
                        if ":" in ip:
                            result["ipv6"].append(ip)
                        else:
                            result["ipv4"].append(ip)

                for cidr in ipv4_cidrs:
                    ip = cidr.get("cidr")
                    if ip:
                        result["ipv4"].append(ip)

                for cidr in ipv6_cidrs:
                    ip = cidr.get("cidr")
                    if ip:
                        result["ipv6"].append(ip)

        return result

    def _transform_vultr(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Vultr data to unified format."""
        result = self._transform_base("vultr")
        data = response[0].json()

        if isinstance(data, dict):
            subnets = data.get("subnets", [])
            for subnet in subnets:
                ip_prefix = subnet.get("ip_prefix")
                if ip_prefix:
                    if ":" in ip_prefix:
                        result["ipv6"].append(ip_prefix)
                    else:
                        result["ipv4"].append(ip_prefix)

        return result

    def _transform_whatsapp(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform WhatsApp data to unified format."""
        result = self._transform_base("microsoft_azure")

        match = re.findall(r"""<a href=\"([^\"]+)\"""", response[0].text)
        data = None
        for u in match:
            if not "fbcdn.net" in u and not ".zip" in u:
                continue

            u = html.unescape(u)
            r = self.session.get(u, timeout=10)
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

    def _transform_microsoft_azure(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Microsoft Azure data to unified format."""
        result = self._transform_base("microsoft_azure")

        match = re.findall(r"""<a href=\"([^\"]+)\"""", response[0].text)
        response = []
        for u in match:
            if not u.startswith("https://download.microsoft.com"):
                continue

            r = self.session.get(u, timeout=10)
            r.raise_for_status()
            response.append(r)

        ipv4 = set()
        ipv6 = set()

        for r in response:
            data = r.json()
            values = data.get("values", [])
            for value in values:
                properties = value.get("properties", {})
                addresses = properties.get("addressPrefixes", [])
                for address in addresses:
                    if ":" in address:
                        ipv6.add(address)
                    else:
                        ipv4.add(address)

        result["ipv4"] = list(ipv4)
        result["ipv6"] = list(ipv6)
        return result

    def _transform_github(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform GitHub data to unified format."""
        result = self._transform_base("github")
        data = response[0].json()

        if isinstance(data, dict):
            for key in ["hooks", "web"]:
                ranges = data.get(key, [])
                for range in ranges:
                    if ":" in range:
                        result["ipv6"].append(range)
                    else:
                        result["ipv4"].append(range)

        return result

    def _transform_ahrefs(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Ahrefs crawler IP ranges to unified format."""
        result = self._transform_base("ahrefs")
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

    def _transform_akamai(self, response: List[requests.Response]) -> Dict[str, Any]:
        """Transform Akamai data to unified format."""
        result = self._transform_base("akamai")
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

    def _transform_response(self, response: List[requests.Response], source_key: str, is_asn: bool) -> Dict[str, Any]:
        if is_asn:
            transformed_data = self._transform_hackertarget(response, source_key)
        else:
            transform_method = getattr(self, f"_transform_{source_key}")
            transformed_data = transform_method(response)

        ipv4 = set()
        ipv6 = set()

        for ip in transformed_data["ipv4"]:
            validated_ip = validate_ip(ip)
            if validated_ip:
                ipv4.add(validated_ip)

        for ip in transformed_data["ipv6"]:
            validated_ip = validate_ip(ip)
            if validated_ip:
                ipv6.add(validated_ip)

        if not ipv4 and not ipv6:
            raise RuntimeError(f"Failed to parse {source_key}")

        transformed_data["ipv4"] = sorted(ipv4)
        transformed_data["ipv6"] = sorted(ipv6)

        return transformed_data

    def _fetch_and_save(self, source_key: str) -> None:
        """Fetch and save IP ranges for a specific source."""
        logging.debug("Fetching %s source", source_key)
        url = self.sources[source_key]

        response = []
        for u in url:
            if u.startswith("AS"):
                u = f"https://api.hackertarget.com/aslookup/?q={u}"
            r = self.session.get(u, timeout=10)
            r.raise_for_status()
            response.append(r)

        transformed_data = self._transform_response(response, source_key, url[0].startswith("AS"))

        if self.only_if_changed:
            json_filename = "{}.json".format(source_key.replace("_", "-"))
            json_path = self.base_url / json_filename

            if json_path.exists():
                with open(json_path, "r") as f:
                    existing_data = json.load(f)

                existing_data.pop("last_update", None)
                new_data = transformed_data.copy()
                new_data.pop("last_update", None)

                if existing_data == new_data:
                    logging.debug("No changes found for %s, skipping other formats", source_key)
                    return

        self._save_result(transformed_data, source_key)

    def _save_result(self, transformed_data: Dict[str, Any], source_key: str):
        for x, output_format in enumerate(self.output_formats):
            filename = "{}.{}".format(source_key.replace("_", "-"), output_format)

            with open(self.base_url / filename, "w") as f:
                if output_format == "json":
                    json.dump(transformed_data, f, indent=2)
                elif output_format == "csv":
                    writer = csv.writer(f)
                    writer.writerow(["Type", "Address"])
                    for ip in transformed_data["ipv4"]:
                        writer.writerow(["IPv4", ip])
                    for ip in transformed_data["ipv6"]:
                        writer.writerow(["IPv6", ip])
                elif output_format == "txt":
                    for k in ("provider", "source", "last_update"):
                        vl = ", ".join(transformed_data[k]) if isinstance(transformed_data[k], list) else transformed_data[k]
                        f.write("# {}: {}\n".format(k, vl))

                    f.write("\n")
                    f.write("\n".join(transformed_data["ipv4"]))
                    if transformed_data["ipv6"]:
                        f.write("\n")
                        f.write("\n".join(transformed_data["ipv6"]))
                else:
                    raise ValueError(f"Unknown output format: {output_format}")

            if x == 0:
                logging.info("Saved %s [IPv4: %d, IPv6: %d]", filename, len(transformed_data["ipv4"]), len(transformed_data["ipv6"]))
            else:
                logging.debug("Saved %s", filename)

    def fetch_all(self, sources: Optional[Set[str]] = None) -> bool:
        error = False
        try:
            for source in self.sources:
                if sources is not None and source not in sources:
                    continue
                try:
                    self._fetch_and_save(source)
                except Exception as e:
                    logging.error("Failed to fetch %s: %s", source, str(e))
                    error = True

        except Exception as e:
            logging.error("Error during IP range collection: %s", e)
            raise

        return not error


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Collect IP ranges from cloud providers")
    parser.add_argument("--sources", nargs="+", choices=CloudIPRanges.sources.keys(), help="Specific sources to update (e.g., aws google_cloud)")
    parser.add_argument("--only-if-changed", action="store_true", help="Only write files if there are changes (only works with JSON format)")
    parser.add_argument(
        "--output-format", nargs="+", choices=["json", "csv", "txt"], default=["json"], help="Output format(s) to save the data in (default: json)"
    )
    args = parser.parse_args()

    # Convert sources to set if specified, otherwise None
    sources = set(args.sources) if args.sources else None

    # Convert sources to set if specified, otherwise None
    sources = set(args.sources) if args.sources else None
    output_formats = set(args.output_format)
    cloud_ip_ranges = CloudIPRanges(output_formats, args.only_if_changed)
    if not cloud_ip_ranges.fetch_all(sources):
        sys.exit(1)


if __name__ == "__main__":
    main()
