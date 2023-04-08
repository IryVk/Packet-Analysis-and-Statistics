import stats
from scapy.all import *


# NOTE: To run this file, install pytest "pip install pytest" and type "pytest test_analyze.py" in the terminal

def test_count():
    """Asserts that count() can correctly distinguish if packet is a control/data"""
    # ARP packet
    packet = Ether() / ARP()
    old_count = stats.CNT
    stats.count(packet, save=False)
    assert stats.CNT == old_count + 1  # Check if count incremented the CNT variable in stats.py
    # DNS packet
    packet = Ether() / IP() / UDP() / DNS()
    old_count = stats.CNT
    stats.count(packet, save=False)
    assert stats.CNT == old_count + 1  # Check if count incremented the CNT variable in stats.py
    # DHCP packet
    packet = Ether() / IP() / UDP() / DHCP()
    old_count = stats.CNT
    stats.count(packet, save=False)
    assert stats.CNT == old_count + 1  # Check if count incremented the CNT variable in stats.py
    
    # Data packet
    packet = Ether() / IP() / TCP()
    old_data = stats.DATA
    stats.count(packet, save=False)
    assert stats.DATA == old_data + 1  # Check if count incremented the DATA variable in stats.py
