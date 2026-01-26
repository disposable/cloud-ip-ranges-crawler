# Cloud IP Ranges Crawler

A Python script to automatically collect and standardize IP address ranges from various cloud providers, bots, and online services.

## Overview

This crawler fetches IP ranges from multiple cloud providers and online services, transforms them into a unified format, and saves them in multiple output formats (JSON, CSV, TXT). It supports both direct API endpoints and ASN-based lookups for providers that don't publish explicit IP ranges.

## Features

- **Multi-provider support**: Collects IP ranges from 40+ cloud providers and services
- **Multiple output formats**: JSON, CSV, and TXT formats
- **Detailed metadata**: Preserves provider-specific information like regions, services, and categories
- **Change detection**: Optional `--only-if-changed` flag to avoid unnecessary file updates
- **Flexible source selection**: Fetch specific providers or all at once
- **Comprehensive validation**: Validates IP addresses and filters out private/local ranges
- **GitHub Actions integration**: Environment variable output for CI/CD pipelines

## Supported Providers

### Direct API Sources
- **Amazon Web Services (AWS)** - IP ranges with service and region details
- **Cloudflare** - IPv4 and IPv6 ranges
- **DigitalOcean** - GeoIP data in CSV format
- **Google Cloud** - Cloud IP ranges with service details
- **Google Bot** - Search crawler IP ranges
- **Bing Bot** - Microsoft search crawler IP ranges
- **Oracle Cloud** - Infrastructure IP ranges with region details
- **Ahrefs** - SEO crawler IP ranges
- **Linode** - Cloud provider IP ranges
- **Vultr** - Cloud hosting IP ranges with geographic details
- **OpenAI** - ChatGPT and GPT Bot IP ranges
- **Perplexity** - AI search engine IP ranges
- **GitHub** - Web hook and action IP ranges
- **Apple Private Relay** - iCloud privacy service IP ranges
- **Starlink** - Satellite ISP IP ranges
- **Akamai** - CDN infrastructure IP ranges
- **Zscaler** - Security service IP ranges (required/recommended)
- **Fastly** - CDN and edge computing IP ranges
- **Microsoft Azure** - Cloud service IP ranges with service details
- **Telegram** - Messaging service IP ranges
- **Atlassian** - Collaboration tools IP ranges
- **Datadog** - Monitoring and security platform IP ranges
- **Okta** - Identity management service IP ranges
- **Zendesk** - Customer support platform IP ranges
- **Vercel** - Edge computing platform IP ranges (registry-owned)

### ASN-based Sources
Providers that don't publish explicit IP ranges are queried through ASN lookups:
- **IBM/Softlayer** (AS36351)
- **Heroku/AWS** (AS14618)
- **Fly.io** (AS40509)
- **Render** (AS397273)
- **A2Hosting** (AS55293)
- **GoDaddy** (AS26496, AS30083)
- **Dreamhost** (AS26347)
- **Alibaba** (AS45102, AS134963)
- **Tencent** (AS45090, AS133478, AS132591, AS132203)
- **Ucloud** (AS135377, AS59077)
- **Meta Crawler** (AS32934)
- **Huawei Cloud** (AS136907, AS55990)
- **Hetzner** (AS24940, AS37153)
- **Choopa** (AS46407, AS20473, AS133795, AS11508)
- **OVH** (AS35540, AS16276)
- **Online SAS** (AS12876)
- **Rackspace** (Multiple ASNs)
- **nForce** (AS64437, AS43350)

## Installation

### Prerequisites
- Python 3.10 or higher
- `uv` package manager (recommended) or pip

### Setup with uv (Recommended)
```bash
# Clone the repository
git clone <repository-url>
cd crawler

# Install dependencies and package
uv sync --no-dev

# Run directly with uv (no activation needed)
uv run cloud-ip-ranges --help

# Or run the Python script directly
uv run python src/cloud_ip_ranges.py --help

# Optionally activate for multiple commands
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
cloud-ip-ranges --help
```

### Setup with pip
```bash
# Install in development mode to get the command
pip install -e .

# Or install dependencies and run with python
pip install -r requirements.txt  # or the dependencies from pyproject.toml
python src/cloud_ip_ranges.py
```

## Usage

### Basic Usage
```bash
# Using uv run (recommended - no activation needed)
uv run cloud-ip-ranges

# Or using the installed binary after activation
source .venv/bin/activate
cloud-ip-ranges

# Or using Python directly
uv run python src/cloud_ip_ranges.py

# Fetch specific providers
uv run cloud-ip-ranges --sources aws google_cloud cloudflare

# Output in multiple formats
uv run cloud-ip-ranges --output-format json csv txt

# Only update if changes detected
uv run cloud-ip-ranges --only-if-changed

# Enable debug logging
uv run cloud-ip-ranges --debug
```

### Advanced Usage
```bash
# Fetch specific providers with multiple output formats
uv run cloud-ip-ranges --sources aws azure --output-format json csv

# Add environment statistics for GitHub Actions
uv run cloud-ip-ranges --add-env-statistics

# Log to file
uv run cloud-ip-ranges --log-file crawler.log
```

### Command Line Options

- `--sources`: Specify which providers to fetch (space-separated list)
- `--output-format`: Output format(s) - `json`, `csv`, `txt` (default: json)
- `--only-if-changed`: Only write files if content has changed
- `--max-delta-ratio`: Reject runs where IP count changes by more than this ratio (e.g., 0.3 = 30%)
- `--add-env-statistics`: Add statistics to environment variables (for CI/CD)
- `--debug`: Enable debug logging
- `--log-file`: Specify log file path

### Output Metadata

All JSON outputs include enhanced metadata:
- `provider_id`: Machine-readable provider identifier
- `method`: How the data was obtained (e.g., `published_list`, `bgp_announced`, `rdap_registry`)
- `coverage_notes`: Scope limitations (e.g., “registry-owned only”)
- `generated_at`: Timestamp when the file was generated
- `source_updated_at`: When the upstream source was last updated
- `source_http`: HTTP response metadata (status, content-type, etag, last-modified)

## Output Formats

### JSON Format
```json
{
  "provider": "Aws",
  "source": "https://ip-ranges.amazonaws.com/ip-ranges.json",
  "last_update": "2024-01-15T12:00:00",
  "ipv4": ["52.94.0.0/16", "54.239.0.0/16"],
  "ipv6": ["2600:1f14::/36", "2600:1f15::/36"],
  "details_ipv4": [
    {
      "address": "52.94.0.0/16",
      "service": "AMAZON",
      "region": "us-east-1",
      "network_border_group": "us-east-1"
    }
  ]
}
```

### CSV Format
```csv
Type,Address
IPv4,52.94.0.0/16
IPv6,2600:1f14::/36
```

### TXT Format
```txt
# provider: Aws
# source: https://ip-ranges.amazonaws.com/ip-ranges.json
# last_update: 2024-01-15T12:00:00

52.94.0.0/16
54.239.0.0/16
2600:1f14::/36
```

## Development

### Code Quality Tools
The project uses comprehensive code quality tools configured in `pyproject.toml`:

```bash
# Run all validation checks
uv run make validate

# Individual tools
uv run make format      # Code formatting check
uv run make check       # Linting and docstrings
uv run make test        # Unit tests
uv run make bandit      # Security analysis
uv run make pyright     # Static type checking
uv run make vulture     # Dead code detection
uv run make complexity  # Cyclomatic complexity analysis
```

### Available Make Targets
- `validate` - Run all quality checks (format, check, complexity, bandit, pyright, vulture)
- `format` - Check code formatting with ruff
- `check` - Run linting checks with ruff
- `fix` - Auto-fix formatting and linting issues
- `test` - Run pytest unit tests
- `bandit` - Security vulnerability scanning
- `pyright` - Static type checking
- `vulture` - Dead code detection
- `complexity` - Code complexity analysis

## Architecture

The crawler is built around the `CloudIPRanges` class which:

1. **Fetches** data from provider URLs or ASN lookups
2. **Transforms** provider-specific formats to a unified structure
3. **Validates** IP addresses and filters private ranges
4. **Saves** results in multiple formats with optional detailed metadata

### Key Components

- `CloudIPRanges.sources`: Dictionary of all supported providers and their data sources
- `_transform_*` methods: Provider-specific data transformation logic
- `validate_ip()`: IP address validation and filtering
- `_save_result()`: Multi-format output generation
- `_audit_transformed_data()`: Sanity checks (no default routes, no private ranges)
- `_enforce_max_delta()`: Delta change enforcement for CI gating

## Data Collection Methods

### Direct API Sources
Providers with official IP range documents/JSON APIs.

### ASN-based Sources (RIPEstat)
Providers without published lists use RIPEstat “Announced Prefixes” for BGP-announced prefixes, with HackerTarget as fallback.

### RDAP-based Sources (Vercel)
For providers that own netblocks but lack ASN, we use:
- Seed CIDRs → RDAP → org handle → ARIN Whois-RWS nets enumeration
- Emits registry-owned netblocks only (not cloud egress/edge IPs)

## Reliability Features

### HTTP Layer Hardening
- Default User-Agent and headers
- Retries with exponential backoff (5 attempts)
- Captures HTTP metadata (status, content-type, etag, last-modified)

### Change Detection
- `--only-if-changed`: Skip writes when content is unchanged
- `--max-delta-ratio`: Reject runs with extreme IP count changes (e.g., >30%)
- Delta summaries logged for CI visibility

### Auditing
- Rejects default routes (0.0.0.0/0, ::/0)
- Filters private/local ranges
- Validates CIDR syntax

## Error Handling

The crawler includes robust error handling:
- HTTP request timeouts and retries
- Invalid IP address filtering
- Provider-specific error detection
- Graceful degradation when individual providers fail

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Run `make validate` to ensure code quality
5. Submit a pull request

## License

See LICENSE file for details.

## Integration with Main Repository

This crawler is designed as a submodule for the main cloud-ip-ranges repository. When run, it generates IP range files that can be committed to the parent repository's data directories (csv/, json/, txt/).

The crawler supports GitHub Actions integration through the `--add-env-statistics` flag, which outputs environment variables for use in CI/CD pipelines.
