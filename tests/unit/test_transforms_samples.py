"""Sample download and format tests."""

import pytest
from pathlib import Path
from typing import Any, Dict, List

from src.cloud_ip_ranges import CloudIPRanges

from tests.unit.conftest import FakeResponse, SAMPLES_DIR


def _transform_response(cipr: CloudIPRanges, response: List[Any], source_key: str, is_asn: bool) -> Dict[str, Any]:
    """Helper function to replace the removed _transform_response method for tests."""
    if is_asn:
        from src.sources.asn import transform_hackertarget

        transformed_data = transform_hackertarget(cipr, response, source_key)
    else:
        from src.transforms.registry import get_transform

        transform_fn = get_transform(source_key)
        transformed_data = transform_fn(cipr, response, source_key)

    return cipr._normalize_transformed_data(transformed_data, source_key)


def test_seed_based_download_sample_format() -> None:
    """Test that seed-based sample files (like Vercel) have the correct format."""
    sample_file = SAMPLES_DIR / "vercel_0.raw"
    assert sample_file.exists(), f"Sample file {sample_file} does not exist"

    content = sample_file.read_text(encoding="utf-8")
    assert content.strip(), "Sample file should not be empty"

    # Verify it's valid JSON
    import json

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        pytest.fail(f"Sample file is not valid JSON: {e}")

    # For seed-based sources like Vercel, we use a mock wrapper that contains rdap_responses
    if "mock_response" in data and "rdap_responses" in data:
        # Check that we have RDAP responses in the expected format
        assert isinstance(data["rdap_responses"], list), "RDAP responses should be a list"
        assert len(data["rdap_responses"]) > 0, "Should have at least one RDAP response"

        # Check the first RDAP response for required fields
        rdap = data["rdap_responses"][0]
        assert "entities" in rdap, "RDAP response should contain 'entities' field"
        assert isinstance(rdap["entities"], list), "Entities should be a list"

        # Verify at least one entity has a handle and roles
        found_valid_entity = False
        for entity in rdap["entities"]:
            if isinstance(entity, dict) and "handle" in entity and "roles" in entity:
                found_valid_entity = True
                break

        assert found_valid_entity, "Should have at least one valid entity with handle and roles"
    else:
        # For non-mock samples, check for direct RDAP fields
        assert "entities" in data, "RDAP response should contain 'entities' field"
        assert isinstance(data["entities"], list), "Entities should be a list"

        # Verify at least one entity has a handle and roles
        found_valid_entity = False
        for entity in data["entities"]:
            if isinstance(entity, dict) and "handle" in entity and "roles" in entity:
                found_valid_entity = True
                break

        assert found_valid_entity, "Should have at least one valid entity with handle and roles"


def test_sample_files_are_valid(cipr: CloudIPRanges) -> None:
    """Test that all sample files can be processed without errors."""
    sample_files = list(SAMPLES_DIR.glob("*.raw"))
    assert len(sample_files) > 0, "No sample files found"

    # Group responses by base source key so multi-endpoint providers can be tested.
    groups: dict[str, list[Path]] = {}
    for sample_file in sample_files:
        base = sample_file.name
        if base.endswith(".raw"):
            base = base[:-4]
        base_key = base.rsplit("_", 1)[0]
        groups.setdefault(base_key, []).append(sample_file)

    for base_key, files in groups.items():
        # Skip microsoft_azure as it requires network calls to download JSON
        # Skip vercel as it requires network calls for RDAP/WHOIS lookups
        # Skip akamai as it's a zip file and FakeResponse doesn't handle binary content properly
        # Skip whatsapp as it requires network calls to download zip
        if base_key.startswith("microsoft") or base_key.startswith("vercel") or base_key.startswith("akamai") or base_key.startswith("whatsapp"):
            continue

        # Map filename prefixes to actual source keys
        source_key = base_key
        if source_key == "apple":
            source_key = "apple_private_relay"
        elif source_key == "oracle":
            source_key = "oracle_cloud"
        elif source_key == "bing":
            source_key = "bing_bot"
        elif source_key == "google":
            source_key = "google_bot"

        # Ensure deterministic ordering for multi-response providers
        files = sorted(files, key=lambda p: p.name)

        responses: List[Any] = [FakeResponse(text=f.read_text(encoding="utf-8")) for f in files]

        try:
            result = _transform_response(cipr, responses, source_key, is_asn=False)

            # Verify basic structure
            assert "provider" in result
            assert "ipv4" in result
            assert "ipv6" in result
            assert isinstance(result["ipv4"], list)
            assert isinstance(result["ipv6"], list)
        except Exception as e:
            pytest.fail(f"Failed to process sample files for {source_key}: {e}")


def test_sample_file_consistency() -> None:
    """Test that sample files are consistent with their expected formats."""
    # Test that Vercel samples are valid RDAP responses (wrapped in mock)
    vercel_samples = list(SAMPLES_DIR.glob("vercel_*.raw"))
    for sample in vercel_samples:
        content = sample.read_text()
        import json

        data = json.loads(content)
        # Handle mock wrapper structure
        if "mock_response" in data and "rdap_responses" in data:
            assert isinstance(data["rdap_responses"], list), f"Vercel sample {sample.name} should have rdap_responses list"
            assert len(data["rdap_responses"]) > 0, f"Vercel sample {sample.name} should have at least one RDAP response"
            rdap = data["rdap_responses"][0]
            assert "entities" in rdap, f"Vercel sample {sample.name} RDAP response should contain 'entities'"
        else:
            assert "entities" in data, f"Vercel sample {sample.name} should be a valid RDAP response"

    # Test that CSV-like samples have the expected format
    csv_samples = ["linode_0.raw", "telegram_0.raw", "starlink_0.raw", "digitalocean_0.raw"]
    for sample_name in csv_samples:
        sample_path = SAMPLES_DIR / sample_name
        if sample_path.exists():
            content = sample_path.read_text()
            lines = content.strip().split("\n")
            assert len(lines) > 1, f"CSV sample {sample_name} should have multiple lines"
            # Check that at least one line looks like a CIDR
            found_cidr = False
            for line in lines:
                if "/" in line and not line.startswith("#"):
                    found_cidr = True
                    break
            assert found_cidr, f"CSV sample {sample_name} should contain at least one CIDR"

    # Test that JSON samples have the expected structure
    json_samples = ["aws_0.raw", "google_cloud_0.raw", "github_0.raw"]
    for sample_name in json_samples:
        sample_path = SAMPLES_DIR / sample_name
        if sample_path.exists():
            content = sample_path.read_text()
            import json

            data = json.loads(content)
            assert isinstance(data, dict), f"JSON sample {sample_name} should be a dictionary"
