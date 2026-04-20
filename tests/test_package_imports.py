"""Smoke tests: verify that netkit modules import cleanly and expose key symbols."""

import shorewall_nft_netkit.nsstub as nsstub
import shorewall_nft_netkit.packets as packets
import shorewall_nft_netkit.tundev as tundev


def test_tundev_symbols():
    assert hasattr(tundev, "create_tuntap")
    assert hasattr(tundev, "close_tuntap")


def test_nsstub_symbols():
    assert hasattr(nsstub, "spawn_nsstub")
    assert hasattr(nsstub, "stop_nsstub")


def test_packets_symbols():
    assert hasattr(packets, "build_tcp")
    assert hasattr(packets, "build_udp")
    assert hasattr(packets, "fast_probe_id")
    assert hasattr(packets, "PacketSummary")
