"""Tests for VPN/proxy provider transforms."""

import importlib
from unittest.mock import Mock

import pytest

from tests.unit.conftest import FakeResponse

GLUETUN_PROVIDERS = [
    "protonvpn",
    "surfshark",
    "cyberghost",
    "expressvpn",
    "fastestvpn",
    "giganews",
    "hidemyass",
    "ipvanish",
    "ovpn",
    "privado",
    "privatevpn",
    "purevpn",
    "slickvpn",
    "torguard",
    "vpn_unlimited",
    "vpnsecure",
    "vyprvpn",
]


def _mock_cipr():
    cipr = Mock()
    cipr._transform_base.return_value = {"ipv4": [], "ipv6": []}
    return cipr


@pytest.mark.parametrize("source_key", GLUETUN_PROVIDERS)
def test_gluetun_servers_transform(source_key):
    mod = importlib.import_module(f"transforms.{source_key}")
    r = FakeResponse(
        json_data={
            "servers": [
                {"ips": ["1.2.3.4", "5.6.7.8"]},
                {"ips": ["2606:4700::1"]},
                {},
            ]
        }
    )
    result = mod.transform(_mock_cipr(), [r], source_key)
    assert result["ipv4"] == ["1.2.3.4", "5.6.7.8"]
    assert result["ipv6"] == ["2606:4700::1"]
    assert "gluetun" in result["coverage_notes"]


def test_gluetun_empty_servers():
    from transforms.protonvpn import transform

    r = FakeResponse(json_data={"servers": []})
    result = transform(_mock_cipr(), [r], "protonvpn")
    assert result["ipv4"] == []
    assert result["ipv6"] == []


def test_mullvad_active_only():
    from transforms.mullvad import transform

    r = FakeResponse(
        json_data=[
            {"active": True, "ipv4_addr_in": "1.2.3.4", "ipv6_addr_in": "2606:4700::1"},
            {"active": False, "ipv4_addr_in": "9.9.9.9", "ipv6_addr_in": "fe80::1"},
        ]
    )
    result = transform(_mock_cipr(), [r], "mullvad")
    assert result["ipv4"] == ["1.2.3.4"]
    assert result["ipv6"] == ["2606:4700::1"]


def test_nordvpn_online_only():
    from transforms.nordvpn import transform

    r = FakeResponse(
        json_data=[
            {"status": "online", "station": "1.2.3.4", "ipv6_station": "2606:4700::1"},
            {"status": "offline", "station": "9.9.9.9"},
            {"status": "online", "station": "", "ipv6_station": ""},
        ]
    )
    result = transform(_mock_cipr(), [r], "nordvpn")
    assert result["ipv4"] == ["1.2.3.4"]
    assert result["ipv6"] == ["2606:4700::1"]


def test_pia_first_line_only_and_vpn_groups():
    from transforms.private_internet_access import transform

    payload = (
        '{"regions": ['
        '{"offline": false, "servers": {"wg": [{"ip": "1.2.3.4"}], "meta": [{"ip": "9.9.9.9"}]}},'
        '{"offline": true, "servers": {"wg": [{"ip": "8.8.8.8"}]}}'
        "]}\nSIGNATURE-BLOB"
    )
    result = transform(_mock_cipr(), [FakeResponse(text=payload)], "private_internet_access")
    assert result["ipv4"] == ["1.2.3.4"]


def test_ivpn_hosts():
    from transforms.ivpn import transform

    r = FakeResponse(
        json_data={
            "wireguard": [{"hosts": [{"host": "1.2.3.4"}, {"host": "5.6.7.8"}]}],
            "openvpn": [{"hosts": [{"host": "9.10.11.12"}]}],
        }
    )
    result = transform(_mock_cipr(), [r], "ivpn")
    assert sorted(result["ipv4"]) == ["1.2.3.4", "5.6.7.8", "9.10.11.12"]


def test_airvpn_server_ips():
    from transforms.airvpn import transform

    r = FakeResponse(
        json_data={
            "servers": [
                {"ip_v4_in1": "1.2.3.4", "ip_v4_in2": "1.2.3.5", "ip_v6_in1": "2606:4700::1"},
                {"ip_v4_in4": "9.9.9.9"},
            ]
        }
    )
    result = transform(_mock_cipr(), [r], "airvpn")
    assert sorted(result["ipv4"]) == ["1.2.3.4", "1.2.3.5", "9.9.9.9"]
    assert result["ipv6"] == ["2606:4700::1"]


def test_windscribe_nodes():
    from transforms.windscribe import transform

    r = FakeResponse(
        json_data={
            "data": [
                {
                    "groups": [
                        {"nodes": [{"ip": "1.2.3.4", "ip2": "1.2.3.5", "ip3": "1.2.3.6"}, {"ip": "5.6.7.8"}]},
                    ]
                }
            ]
        }
    )
    result = transform(_mock_cipr(), [r], "windscribe")
    assert sorted(result["ipv4"]) == ["1.2.3.4", "1.2.3.5", "1.2.3.6", "5.6.7.8"]


def test_tor_exit_list():
    from transforms.tor import transform

    r = FakeResponse(text="1.2.3.4\n5.6.7.8\n# comment\n\n")
    result = transform(_mock_cipr(), [r], "tor")
    assert sorted(result["ipv4"]) == ["1.2.3.4", "5.6.7.8"]


def test_cloudflare_warp_csv():
    from transforms.cloudflare_warp import transform

    r = FakeResponse(text="1.2.3.0/24,US,California,SF\n2606:4700::/64,US,California,SF\ninvalid,X,Y,Z\n")
    result = transform(_mock_cipr(), [r], "cloudflare_warp")
    assert "1.2.3.0/24" in result["ipv4"]
    assert "2606:4700::/64" in result["ipv6"]
