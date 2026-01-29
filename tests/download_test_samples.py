import logging
import os
import sys
from pathlib import Path
import requests
import json

# Add the parent directory to Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
sys.path.append(parent_dir)

from src.cloud_ip_ranges import CloudIPRanges


def download_raw_samples():
    """Download raw source data for testing transformation methods."""
    # Create the output directory if it doesn't exist
    output_dir = Path(__file__).parent / "samples"
    output_dir.mkdir(exist_ok=True)

    # Get the sources from CloudIPRanges
    cloud_ip_ranges = CloudIPRanges(output_formats={"json"})

    # Download raw data for each source
    for source, urls in cloud_ip_ranges.sources.items():
        if isinstance(urls, str):
            urls = [urls]

        # Handle sources that use seed CIDRs for RDAP lookups (not traditional URLs)
        # These are identified by CIDR notation (e.g., "76.76.21.0/24") rather than URLs
        if urls and any("/" in url and "." in url.split("/")[0] for url in urls):
            # This looks like CIDR notation, not URLs
            logging.info(f"Handling seed-based source {source} with CIDRs: {urls}")
            try:
                # For seed-based sources, we need to simulate the RDAP lookup process
                # Create mock RDAP responses for each seed CIDR
                mock_responses = []
                for seed in urls:
                    seed.split("/")[0]
                    # Mock RDAP registry response for the seed IP
                    mock_rdap = {"entities": [{"handle": f"{source.upper()}-ARIN-HANDLE", "roles": ["registrant"], "name": f"{source.title()} Inc."}]}
                    mock_responses.append(mock_rdap)

                # Create a mock file that contains the array of mock responses
                mock_data = {
                    "mock_response": True,
                    "source": source,
                    "seeds": urls,
                    "rdap_responses": mock_responses,
                    "note": f"{source} uses RDAP lookups from seed CIDRs. This mock simulates the ARIN registry responses.",
                }

                output_file = output_dir / f"{source}_0.raw"
                with open(output_file, "w") as f:
                    json.dump(mock_data, f, indent=2)

                logging.info(f"Created mock {source} sample with {len(mock_responses)} RDAP responses: {output_file}")
                continue

            except Exception as e:
                logging.error(f"Error creating mock {source} data: {e}")
                continue

        # Skip ASN-based sources (they start with "AS")
        if urls and urls[0].startswith("AS"):
            logging.info(f"Skipping ASN-based source: {source}")
            continue

        try:
            for i, url in enumerate(urls):
                try:
                    response = requests.get(url, timeout=10)
                    response.raise_for_status()

                    # Save the raw response
                    if url.endswith(".json"):
                        data = response.json()
                    else:
                        data = response.text

                    # Create a filename based on the source and URL index
                    output_file = output_dir / f"{source}_{i}.raw"
                    with open(output_file, "w") as f:
                        if isinstance(data, dict):
                            json.dump(data, f, indent=2)
                        else:
                            f.write(data)

                    logging.info(f"Downloaded {source}_{i}.raw")

                except requests.RequestException as e:
                    logging.error(f"Error downloading {url}: {e}")
                    continue

        except Exception as e:
            logging.error(f"Error processing {source}: {e}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    download_raw_samples()
