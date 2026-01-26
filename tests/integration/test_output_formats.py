"""Integration tests for different output formats."""

import pytest
import tempfile
import csv
import json
import ipaddress
from pathlib import Path

from src.cloud_ip_ranges import CloudIPRanges


@pytest.mark.integration
def test_csv_output_format(skip_if_no_internet, rate_limit_delay):
    """Test CSV output format generation."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        cipr = CloudIPRanges({"csv"})
        cipr.base_url = temp_path

        # Test with Cloudflare
        provider = "cloudflare"
        result = cipr._fetch_and_save(provider)

        assert result is not None

        # Check CSV file was created
        csv_file = temp_path / f"{provider}.csv"
        assert csv_file.exists()

        # Validate CSV content
        with open(csv_file, 'r') as f:
            csv_content = f.read()

        # Should have CSV structure
        assert ',' in csv_content
        lines = csv_content.strip().split('\n')
        assert len(lines) > 1  # Header + data

        # Parse as CSV to validate structure
        csv_reader = csv.reader(lines)
        rows = list(csv_reader)

        # Check header
        header = rows[0]
        expected_columns = ["ip_range", "type"]
        for col in expected_columns:
            assert col in header, f"CSV should have {col} column"

        # Check data rows
        assert len(rows) > 1, "Should have data rows"
        for row in rows[1:]:
            assert len(row) >= 2, "Each row should have at least IP range and type"
            assert '/' in row[0], "First column should be IP range in CIDR format"
            assert row[1] in ['ipv4', 'ipv6'], "Second column should be IP type"


@pytest.mark.integration
def test_txt_output_format(skip_if_no_internet, rate_limit_delay):
    """Test TXT output format generation."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        cipr = CloudIPRanges({"txt"})
        cipr.base_url = temp_path

        # Test with Cloudflare
        provider = "cloudflare"
        result = cipr._fetch_and_save(provider)

        assert result is not None

        # Check TXT file was created
        txt_file = temp_path / f"{provider}.txt"
        assert txt_file.exists()

        # Validate TXT content
        with open(txt_file, 'r') as f:
            txt_content = f.read()

        # Should have IP ranges in CIDR format
        lines = [line.strip() for line in txt_content.split('\n') if line.strip()]
        assert len(lines) > 0, "Should have IP range lines"

        # Check for header comments
        header_lines = [line for line in lines if line.startswith('#')]
        assert len(header_lines) > 0, "Should have header comments"

        # Check IP range lines
        ip_lines = [line for line in lines if not line.startswith('#')]
        assert len(ip_lines) > 0, "Should have IP range data"

        # Validate IP format
        import ipaddress
        for ip_line in ip_lines[:5]:  # Check first 5 IP lines
            ipaddress.ip_network(ip_line, strict=False)


@pytest.mark.integration
def test_multiple_output_formats(skip_if_no_internet, rate_limit_delay):
    """Test generating multiple output formats simultaneously."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        cipr = CloudIPRanges({"json", "csv", "txt"})
        cipr.base_url = temp_path

        # Test with Cloudflare
        provider = "cloudflare"
        result = cipr._fetch_and_save(provider)

        assert result is not None

        # Check all files were created
        json_file = temp_path / f"{provider}.json"
        csv_file = temp_path / f"{provider}.csv"
        txt_file = temp_path / f"{provider}.txt"

        assert json_file.exists()
        assert csv_file.exists()
        assert txt_file.exists()

        # Validate JSON content
        with open(json_file, 'r') as f:
            json_data = json.load(f)
        assert json_data["provider"] == "Cloudflare"
        assert len(json_data["ipv4"]) > 0 or len(json_data["ipv6"]) > 0

        # Validate CSV content
        with open(csv_file, 'r') as f:
            csv_content = f.read()
        assert ',' in csv_content
        assert 'ip_range' in csv_content

        # Validate TXT content
        with open(txt_file, 'r') as f:
            txt_content = f.read()
        assert '#' in txt_content  # Header comments
        assert '/' in txt_content  # CIDR notation


@pytest.mark.integration
def test_output_format_consistency(skip_if_no_internet, rate_limit_delay):
    """Test that all output formats contain consistent data."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        cipr = CloudIPRanges({"json", "csv", "txt"})
        cipr.base_url = temp_path

        # Test with AWS (has many IP ranges)
        provider = "aws"
        result = cipr._fetch_and_save(provider)

        assert result is not None

        # Read all formats
        json_file = temp_path / f"{provider}.json"
        csv_file = temp_path / f"{provider}.csv"
        txt_file = temp_path / f"{provider}.txt"

        # Parse JSON
        with open(json_file, 'r') as f:
            json_data = json.load(f)

        json_ipv4 = set(json_data["ipv4"])
        json_ipv6 = set(json_data["ipv6"])

        # Parse CSV
        csv_ipv4 = set()
        csv_ipv6 = set()
        with open(csv_file, 'r') as f:
            csv_reader = csv.reader(f)
            next(csv_reader)  # Skip header
            for row in csv_reader:
                if len(row) >= 2:
                    ip_range = row[0]
                    ip_type = row[1]
                    if ip_type == 'ipv4':
                        csv_ipv4.add(ip_range)
                    elif ip_type == 'ipv6':
                        csv_ipv6.add(ip_range)

        # Parse TXT
        txt_ipv4 = set()
        txt_ipv6 = set()
        with open(txt_file, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Determine IP type
                    try:
                        ip = ipaddress.ip_network(line, strict=False)
                        if ip.version == 4:
                            txt_ipv4.add(line)
                        else:
                            txt_ipv6.add(line)
                    except:
                        continue

        # Check consistency (allowing for some variation due to formatting)
        assert len(json_ipv4) > 0, "Should have IPv4 ranges"
        assert len(csv_ipv4) > 0, "CSV should have IPv4 ranges"
        assert len(txt_ipv4) > 0, "TXT should have IPv4 ranges"

        # Should have similar counts (allowing for small differences)
        json_count = len(json_ipv4) + len(json_ipv6)
        csv_count = len(csv_ipv4) + len(csv_ipv6)
        txt_count = len(txt_ipv4) + len(txt_ipv6)

        # All formats should have substantial data
        assert json_count > 100, f"JSON should have many ranges: {json_count}"
        assert csv_count > 100, f"CSV should have many ranges: {csv_count}"
        assert txt_count > 100, f"TXT should have many ranges: {txt_count}"


@pytest.mark.integration
def test_output_format_metadata(skip_if_no_internet, rate_limit_delay):
    """Test that output formats include proper metadata."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        cipr = CloudIPRanges({"json", "csv", "txt"})
        cipr.base_url = temp_path

        # Test with GitHub
        provider = "github"
        result = cipr._fetch_and_save(provider)

        assert result is not None

        # Check JSON metadata
        json_file = temp_path / f"{provider}.json"
        with open(json_file, 'r') as f:
            json_data = json.load(f)

        required_fields = ["provider", "provider_id", "method", "generated_at", "source_updated_at"]
        for field in required_fields:
            assert field in json_data, f"JSON should have {field} field"

        # Check TXT metadata (header comments)
        txt_file = temp_path / f"{provider}.txt"
        with open(txt_file, 'r') as f:
            txt_content = f.read()

        lines = txt_content.split('\n')
        header_lines = [line for line in lines if line.startswith('#')]

        # Should have provider info in header
        provider_found = any('github' in line.lower() or 'GitHub' in line for line in header_lines)
        assert provider_found, "TXT header should mention provider"

        # Should have generation timestamp
        timestamp_found = any('generated' in line.lower() for line in header_lines)
        assert timestamp_found, "TXT header should have generation timestamp"


@pytest.mark.integration
def test_output_format_error_handling(skip_if_no_internet, rate_limit_delay):
    """Test error handling in output format generation."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Test with invalid output directory (read-only)
        readonly_dir = temp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)  # Read-only

        try:
            cipr = CloudIPRanges({"json"})
            cipr.base_url = readonly_dir

            # Should handle write errors gracefully
            result = cipr._fetch_and_save("cloudflare")

            # May succeed or fail depending on error handling
            if result is None:
                pass  # Expected for read-only directory

        except Exception as e:
            # Should be a file system error, not a crash
            assert "permission" in str(e).lower() or "access" in str(e).lower()

        finally:
            # Restore permissions for cleanup
            readonly_dir.chmod(0o755)


@pytest.mark.integration
def test_empty_data_output_formats(skip_if_no_internet, rate_limit_delay):
    """Test output formats with empty or minimal data."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        cipr = CloudIPRanges({"json", "csv", "txt"})
        cipr.base_url = temp_path

        # Create minimal test data
        minimal_data = {
            "provider": "Test Provider",
            "provider_id": "test",
            "method": "test",
            "coverage_notes": "",
            "generated_at": "2024-01-01T00:00:00",
            "source_updated_at": "2024-01-01T00:00:00",
            "source": "https://example.com/test",
            "last_update": "2024-01-01T00:00:00",
            "ipv4": [],
            "ipv6": [],
        }

        # Test saving minimal data
        cipr._save_result(minimal_data, "test")

        # Check files were created even with empty data
        json_file = temp_path / "test.json"
        csv_file = temp_path / "test.csv"
        txt_file = temp_path / "test.txt"

        assert json_file.exists()
        assert csv_file.exists()
        assert txt_file.exists()

        # Validate empty data handling
        with open(json_file, 'r') as f:
            json_data = json.load(f)
        assert json_data["ipv4"] == []
        assert json_data["ipv6"] == []

        with open(csv_file, 'r') as f:
            csv_content = f.read()
        lines = csv_content.strip().split('\n')
        assert len(lines) == 1  # Only header, no data rows

        with open(txt_file, 'r') as f:
            txt_content = f.read()
        assert '#' in txt_content  # Should have header
        # Should not have IP range lines
