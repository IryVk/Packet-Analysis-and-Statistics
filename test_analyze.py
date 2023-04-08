import ipaddress

from scapy.all import *
from analyze import *


# NOTE: To run this file, install pytest "pip install pytest" and type "pytest test_analyze.py" in the terminal

IFACE = "Wi-Fi"  # Network intefrace used, change accodrding to interface used


def test_getHost():
    """Assert that getHost() returns vaild IPv4 address and subnet mask"""
    host, mask = getHost(IFACE)
    try:
        ipaddress.IPv4Address(host)
        ipaddress.IPv4Address(mask)
    except AddressValueError as exception:
        assert False, f"{exception}"


def test_isPrivate():
    """Asserts that isPrivate() can correctly differentiate between public and private IPv4 addresses"""
    # Class A example
    assert isPrivate("10.2.3.245")
    assert not isPrivate("9.3.2.1")
    # Class B example
    assert isPrivate("172.17.3.245")
    assert not isPrivate("172.48.2.1")
    # Class C example
    assert isPrivate("192.168.3.245")
    assert not isPrivate("193.3.2.1")


def test_getClass():
    """Asserts that getClass() can correctly determine IP class"""
    assert getClass("9.3.2.1") == "a"
    assert getClass("172.48.2.1") == "b"
    assert getClass("193.3.2.1") == "c"


def test_isSubnetted():
    """Asserts that isSubnetted() can correctly idenfity if network is subnetted"""
    # Class A example
    assert not isSubnetted("9.3.2.1", "255.0.0.0")
    assert isSubnetted("9.3.2.1", "255.255.0.0")
    # Class B example
    assert not isSubnetted("172.48.2.1", "255.255.0.0")
    assert isSubnetted("172.48.2.1", "255.255.255.0")
    # Class C example
    assert not isSubnetted("193.3.2.1", "255.255.255.0")
    assert isSubnetted("193.3.2.1", "255.255.255.128")


def test_getNetId():
    """Asserts that getNetId() can correctly identify network ID"""
    assert getNetId("192.168.1.130", "255.255.255.128") == "192.168.1.128"
    assert getNetId("192.168.60.33", "255.255.255.224") == "192.168.60.32"


def test_getBroadcast():
    """Asserts that getBroadcast() can reliably find broadcast address if possible"""

    assert getBroadcast("192.168.1.130", "255.255.255.128") == "192.168.1.255"
    assert getBroadcast("192.168.60.33", "255.255.255.224") == "192.168.60.63"


def test_cidrToMask():
    """Asserts that cidrToMask() can correctly find subnet mask from cidr notation"""
    assert cidrToMask("192.168.60.33/27") == "255.255.255.224"
    assert cidrToMask("192.168.60.33/25") == "255.255.255.128"


def test_maskToCidr():
    """Asserts that maskToCidr() can correctly find cidr from subnet mask"""
    assert maskToCidr("192.168.60.33", "255.255.255.224") == "192.168.60.33/27"
    assert maskToCidr("192.168.60.33", "255.255.255.128") == "192.168.60.33/25"


def test_getSubnet():
    """Asserts that getSubnet() can reliably find subnet mask if possible"""
    host, host_subnet = getHost(IFACE)

    random_priv = host.split(".")
    random_priv[3] = str(int(host.split(".")[3]) + 1)
    random_priv = ".".join(random_priv)

    # If ip addr equals host addr
    assert getSubnet(ip_addr=host, host_ip=host, host_mask=host_subnet) == host_subnet
    # If ip is random ip on same network
    assert (
        getSubnet(ip_addr=random_priv, host_ip=host, host_mask=host_subnet)
        == host_subnet
    )
    # If ip is random priv ip but not on same network
    assert not getSubnet(ip_addr="172.31.255.2", host_ip=host, host_mask=host_subnet)
    # If ip is a public ip
    try:
        ipaddress.IPv4Address(
            getSubnet(ip_addr="1.0.2.3", host_ip=host, host_mask=host_subnet)
        )
    except AddressValueError as exception:
        assert False, f"{exception}"


def test_translatePort():
    """Asserts that translatePort() can correctly identify ports"""
    # Well-known ports example
    assert translatePort(443, "tcp")["type"] == "Well-known"
    assert translatePort(443, "tcp")["name"] == "https"

    assert translatePort(53, "udp")["type"] == "Well-known"
    assert translatePort(53, "udp")["name"] == "domain"

    # Registered ports example
    assert translatePort(1119, "tcp")["type"] == "Registered"
    assert translatePort(1119, "tcp")["name"] == "bnetgame"
    assert translatePort(5371, "tcp")["type"] == "Registered"

    # Dynamic/private ports example
    assert translatePort(50000, "tcp")["type"] == "Dynamic/Private"


def test_analyzeL2():
    """Asserts that analyzeL2() produces correct info using a packet built by scapy"""
    packet = Ether() / IP() / TCP()
    info = analyzeL2(packet)
    assert info["src"] == packet[Ether].src
    assert info["dst"] == packet[Ether].dst
    assert info["proto"] == ETHER_TYPES[packet[Ether].type]


def test_analyzeL3():
    """Asserts that analyzeL3() produces correct info using a packet built by scapy"""
    packet = Ether() / IP() / TCP()
    info = analyzeL3(packet)

    assert info["src"] == packet[IP].src
    assert info["dst"] == packet[IP].dst

    # Table to translate protocol numbers to name
    prefix = "IPPROTO_"
    proto_table = {
        num: name[len(prefix) :]
        for name, num in vars(socket).items()
        if name.startswith(prefix)
    }

    assert info["proto"] == proto_table[packet[IP].proto]
    assert info["ver"] == packet[IP].version


def test_analyzeL4():
    """Asserts that analyzeL4() produces correct info using a packet built by scapy"""
    packet = Ether() / IP() / TCP()
    info = analyzeL4(packet)

    assert info["src_port"]["port"] == packet[TCP].sport
    assert info["dst_port"]["port"] == packet[TCP].dport
