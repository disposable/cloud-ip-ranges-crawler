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
        if urls[0].startswith("AS"):
            continue

        try:
            for i, url in enumerate(urls):
                try:
                    response = requests.get(url, timeout=10)
                    response.raise_for_status()

                    # Save the raw response
                    if url.endswith('.json'):
                        data = response.json()
                    else:
                        data = response.text

                    # Create a filename based on the source and URL index
                    output_file = output_dir / f"{source}_{i}.raw"
                    with open(output_file, 'w') as f:
                        if isinstance(data, dict):
                            json.dump(data, f, indent=2)
                        else:
                            f.write(data)

                except requests.RequestException as e:
                    logging.error(f"Error downloading {url}: {e}")
                    continue

        except Exception as e:
            logging.error(f"Error processing {source}: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    download_raw_samples()
