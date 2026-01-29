# Cloud IP Ranges Crawler

Automate the collection of public IP ranges from major cloud providers, bots, and supporting services. The crawler fetches upstream data, normalizes it, and emits JSON/CSV/TXT snapshots that can be consumed by allowlists, firewalls, or monitoring pipelines.

## Highlights

- Covers 50+ providers from official documents, BGP lookups, and RDAP expansion
- Consistent metadata (provider id, method, timestamps, HTTP headers)
- Change detection guards (`--only-if-changed`, `--max-delta-ratio`)
- Built-in CI/CD hooks through environment statistics output

## Supported sources

Providers are defined in `CloudIPRanges.sources`, split between:

1. **Published lists** - AWS, Azure, Cloudflare, GitHub, Stripe, etc.
2. **ASN expansion** - RIPEstat + RADB AS-SET lookups when vendors lack allowlists.
3. **RDAP lookups** - Registry-owned netblocks for providers such as Vercel.

See `src/sources/` for the latest definitions; new providers usually only require a small transform module.

### Direct API sources

- **Amazon Web Services (AWS)** - Service + region metadata
- **Cloudflare** - IPv4/IPv6 prefixes
- **DigitalOcean** - GeoIP CSV export
- **Google Cloud** - Service-tagged ranges
- **Google Bot / Bing Bot** - Search crawler IPs
- **Oracle Cloud** - Region-aware IP lists
- **Exoscale** - JSON feed with zone metadata
- **Scaleway** - Network documentation HTML scrape
- **Backblaze** - IP address documentation HTML scrape
- **Cisco Webex** - Media/meetings network requirements HTML scrape
- **STACKIT** - API endpoint with JSON/text fallback
- **Ahrefs**, **Sentry**, **Datadog**, **Branch**, **Perplexity**, **OpenAI**, **Telegram**, **Atlassian**, **Intercom**, **Zendesk**
- **Linode**, **Vultr**, **Starlink**, **Fastly**, **Akamai**, **Zscaler**
- **GitHub**, **CircleCI**, **HCP Terraform**, **New Relic Synthetics**, **Grafana Cloud**
- **Okta**, **Stripe**, **Adyen**, **Salesforce Hyperforce**, **Vercel** (registry-owned blocks)

### ASN-based sources

When providers lack published lists, the crawler performs BGP lookups via RIPEstat and optionally expands RADB AS-SETs (`RADB::AS-SET`). A few examples:

| Provider | Definition |
| --- | --- |
| IBM / Softlayer | `RADB::AS-SOFTLAYER` |
| Heroku (AWS) | `AS14618` |
| Fly.io | `AS40509` |
| Render | `AS397273` |
| GoDaddy | `AS26496`, `AS30083` |
| Alibaba Cloud | `RADB::AS-ALIBABA-CN-NET`, `AS134963` |
| Tencent Cloud | `RADB::AS132203:AS-TENCENT` |
| Hetzner / xneelo | `RADB::AS-HETZNER` |
| OVH | `RADB::AS-OVH` |
| Rackspace | `RADB::AS-RACKSPACE` |
| UpCloud | `AS202053`, `AS25697` |
| gridscale | `AS29423` |
| Aruba Cloud | `AS200185` |
| IONOS Cloud | `AS8560` |
| CYSO Cloud | `AS25151` |
| Seeweb | `AS12637` |
| Open Telekom Cloud | `AS6878` |
| Wasabi | `AS395717` |
| Kamatera | `AS36007` |

### Misc providers

Additional ISP-style exports (e.g., Starlink residential ranges) are stored under `misc/` and can be generated via `--misc` flags.

### Recently added providers

The following providers were recently added with enhanced source validation and error handling:

**Direct API sources:**
- **Exoscale** - Official JSON feed with IPv4/IPv6 prefixes and zone metadata
- **Scaleway** - HTML scraper for network documentation page with CIDR lists
- **Backblaze** - HTML scraper for IP address documentation covering B2 and backup services
- **Cisco Webex** - Multi-page HTML scraper for media and meetings network requirements
- **STACKIT** - API endpoint parser with JSON/text fallback support

**ASN-based sources:**
- **UpCloud** - Multi-ASN provider (AS202053, AS25697) with RIPEstat BGP lookups
- **gridscale** - Single ASN (AS29423) with announced prefix collection
- **Aruba Cloud** - German cloud provider (AS200185) via BGP announcements
- **IONOS Cloud** - European provider (AS8560) with comprehensive prefix coverage
- **CYSO Cloud** - Dutch provider (AS25151) with BGP-derived ranges
- **Seeweb** - Italian provider (AS12637) via ASN prefix lookup
- **Open Telekom Cloud** - Deutsche Telekom cloud (AS6878) with scoped ranges
- **Wasabi** - Storage provider (AS395717) with best-effort IP collection
- **Kamatera** - Multi-region provider (AS36007) via BGP announcements

All new providers include strict CIDR validation (IPv4: /1-32, IPv6: /1-128), comprehensive error handling, and fallback mechanisms where applicable.

## Quick start

Prerequisites: Python 3.10+, and either [uv](https://github.com/astral-sh/uv) (recommended) or pip.

```bash
git clone <repository-url>
cd crawler

# Recommended: manage the virtual env with uv
uv sync --no-dev
uv run cloud-ip-ranges --help

# Alternative: pip
pip install -e .
python src/cloud_ip_ranges.py --help
```

## Usage

```bash
# Fetch everything with defaults
uv run cloud-ip-ranges

# Limit to specific providers and emit multiple formats
uv run cloud-ip-ranges --sources aws google_cloud cloudflare --output-format json csv txt

# Generate "misc" sources (e.g., Starlink ISP list) only
uv run cloud-ip-ranges --misc

# Skip writes when nothing changed and enforce a 30% delta guardrail
uv run cloud-ip-ranges --only-if-changed --max-delta-ratio 0.3

# Provide CI-friendly statistics
uv run cloud-ip-ranges --add-env-statistics
```

### Common flags

| Flag | Purpose |
| --- | --- |
| `--sources ...` | Space-separated list of providers to fetch.
| `--output-format json csv txt` | Control emitted files (default: JSON only).
| `--merge-all-providers` | When set, the crawler also emits `all-providers.json`, `all-providers.csv`, and `all-providers.txt` (matching the selected formats). These merged files consolidate every IPv4/IPv6 CIDR plus provider summaries, making it easy to consume the full dataset with a single artifact.
| `--misc` | Generate ISP-style providers stored under `misc/`.
| `--only-if-changed` | Writes files only when content differs.
| `--max-delta-ratio 0.3` | Reject runs with large IP-count swings.
| `--debug` / `--log-file` | Verbose logging to stdout or a file.

## Output formats

Each provider snapshot contains normalized IPv4/IPv6 lists plus metadata (timestamps, acquisition method, upstream HTTP details). Outputs land in `json/`, `csv/`, and `txt/` directories depending on the requested formats.

## Development

```bash
# Run all validations (format, lint, tests, security, types, etc.)
uv run make validate

# Common individual targets
uv run make format
uv run make check
uv run make test
```

Please add tests for new providers or transforms and ensure `make validate` passes before submitting a PR.

## License

See [LICENSE](LICENSE).

## Integration notes

This repository feeds the main `cloud-ip-ranges` dataset. Generated files can be copied into the parent repo’s `csv/`, `json/`, and `txt/` directories, and the `--add-env-statistics` flag provides GitHub Actions outputs for automated publishing.
