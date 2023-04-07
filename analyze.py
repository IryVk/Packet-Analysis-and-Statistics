import socket
import whatportis as w

from ipwhois import IPWhois
from scapy.all import *


IFACE = "Wi-Fi"  # Network intefrace used

# Table to translate protocol numbers to name
prefix = "IPPROTO_"
proto_table = {
    num: name[len(prefix) :]
    for name, num in vars(socket).items()
    if name.startswith(prefix)
}


def getHost(iface):
    """Get Host IP and Subnet Mask (only works on windows)"""
    proc = subprocess.Popen("ipconfig", stdout=subprocess.PIPE)  # Run ipcofig command
    while True:
        # Read lines until correct network interface is found
        line = proc.stdout.readline()
        if iface.encode() in line:
            # Skip 3 lines
            for _ in range(3):
                line = proc.stdout.readline()
            break
    # Read IPv4 addr and subnet mask
    hostIp = proc.stdout.readline().rstrip().split(b":")[-1].replace(b" ", b"").decode()
    mask = proc.stdout.readline().rstrip().split(b":")[-1].replace(b" ", b"").decode()
    return hostIp, mask


def isPrivate(ip_addr):
    """Determines if an IP address belongs to the public or private ranges"""
    ip_octets = ip_addr.split(".")  # Splits ip into 4 octets

    # Returns True if in any private range, otherwise returns False
    return (
        (ip_octets[0] == "10")
        or (ip_octets[0] == "172" and 16 <= int(ip_octets[1]) <= 31)
        or (ip_octets[0] == "192" and ip_octets[1] == "168")
    )


def getClass(ip_addr):
    """Know an IP address class"""
    ip_octets = ip_addr.split(".")  # Splits ip into 4 octets

    # Checks which class range ip belongs to
    if 1 <= int(ip_octets[0]) <= 126:
        return "a"
    if 128 <= int(ip_octets[0]) <= 191:
        return "b"
    if 192 <= int(ip_octets[0]) <= 223:
        return "c"


def isSubnetted(ip_addr, mask):
    """Know if an IP address is classless or classful"""
    ip_class = getClass(ip_addr)

    # Returns False if ip has default subnet mask, i.e. not subnetted
    return not (
        (ip_class == "a" and mask == "255.0.0.0")
        or (ip_class == "b" and mask == "255.255.0.0")
        or (ip_class == "c" and mask == "255.255.255.0")
    )


def getNetId(ip_addr, mask):
    """Gets network ID of IP address"""
    ip_octets = ip_addr.split(".")  # Splits ip into 4 octets
    mask_octets = mask.split(".")
    ip_bin = [
        int(x) for x in ip_octets
    ]  # Convert octets to binary to preform logical & operation
    mask_bin = [int(x) for x in mask_octets]

    # Iterate over each octet to preform & operation and get network id
    net_id = ""
    for i in range(4):
        net_id += str(ip_bin[i] & mask_bin[i]) + "."  # convert binary to decimal
    return net_id[:-1]


def getBroadcast(ip_addr, mask):
    """Gets broadcast address for the ip address"""
    ip_octets = ip_addr.split(".")  # Splits ip into 4 octets
    mask_octets = mask.split(".")
    ip_bin = [
        int(x) for x in ip_octets
    ]  # Convert octets to binary to preform logical or operation
    mask_bin = [int(x) for x in mask_octets]

    # Iterate over octet to preform or operation to the bitwise not of the mask
    broad = ""
    for i in range(4):
        broad += (
            str((ip_bin[i] | ~mask_bin[i]) & 0xFF) + "."
        )  # convert binary to decimal
    return broad[:-1]


def cidrToMask(cidr):
    """Converts CIDR to Subnet Mask"""
    cidr = cidr.split("/")  # Gets number of bits
    temp = []
    mask = ""
    for _ in range(int(cidr[1])):
        temp.append(1)  # Append 1's to temp according to cidr
    for _ in range(32 - int(cidr[1])):
        temp.append(0)  # Fill remaining bits with 0's
    for _ in range(4):
        mask += (
            str(sum(val * (2**idx) for idx, val in enumerate(reversed(temp[:8]))))
            + "."
        )  # convert binary to decimal
        temp = temp[8:]
    return mask[:-1]


def maskToCidr(ip_addr, mask):
    """Converts Subnet Mask to CIDR"""
    mask_octets = mask.split(".")  # Splits mask into 4 octets
    mask_bin = [bin(int(x) + 256)[3:] for x in mask_octets]  # Convert to binary
    cidr = 0
    # Count number of 1's in mask to find cidr
    for byte in mask_bin:
        for bit in byte:
            if bit == "1":
                cidr += 1
    return ip_addr + "/" + str(cidr)


HOST_IP, HOST_SUBNET = getHost(IFACE)  # Find Host IP and Host Subnet


def getSubnet(ip_addr, host_ip=None, host_mask=None):
    """Get subnet mask of IP if possible"""
    global HOST_IP, HOST_SUBNET

    # If host_ip and host_mask are not given, use global host and mask variables
    if host_ip is None:
        host_ip = HOST_IP
    if host_mask is None:
        host_mask = HOST_SUBNET

    if isPrivate(ip_addr):
        if ip_addr == host_ip:  # If the ip belongs to host return host subnet
            return host_mask
        if getNetId(host_ip, host_mask) == getNetId(
            ip_addr, host_mask
        ):  # If the ip has same network id
            return host_mask
        return None  # Return None if subnet mask cannot be found

    # If it is a public ip, perform a whois query to find cidr
    try:
        obj = IPWhois(ip_addr)
        res = obj.lookup_whois()
        if cidr := res["nets"][0]["cidr"]:
            return cidrToMask(cidr)
    except:
        pass
    # If we cant find mask from whois query, return None
    return None


def translatePort(port, proto):
    """Translate port number to application/service"""
    # Well-known ports
    if 0 <= port <= 1023:
        ports = w.get_ports(
            str(port)
        )  # Use whatisport library to translate port number to service
        for prt in ports:
            # If we can find the name and description, return dictionary of info
            if proto in prt.protocol:
                return {
                    "port": port,
                    "type": "Well-known",
                    "name": prt.name,
                    "desc": prt.description,
                }
        # If we can't find name, return port number only
        return {
            "port": port,
            "type": "Well-known",
            "name": None,
            "desc": None,
        }
    # Registered ports
    elif 1024 <= port <= 49151:
        ports = w.get_ports(
            str(port)
        )  # Use whatisport library to translate port number to service
        for prt in ports:
            # If we can find the name and description, return dictionary of info
            if proto in prt.protocol:
                return {
                    "port": port,
                    "type": "Registered",
                    "name": prt.name,
                    "desc": prt.description,
                }
        # If we can't find name, return port number only
        return {
            "port": port,
            "type": "Registered",
            "name": None,
            "desc": None,
        }
    # Dynamic/Private ports
    else:
        return {
            "port": port,
            "type": "Dynamic/Private",
            "name": None,
            "desc": None,
        }


def analyzeL2(packet):
    """Analyzes layer 2 of the packet"""
    # PDU header info
    eth_pdu_type = ("Ethernet II" if packet.name == "Ethernet" else packet.name)  # 802.3, 802.11, Ethernet ii,...
    src_mac = packet.src
    dst_mac = packet.dst

    # If packet is Ethernet II packet find protocol
    if packet.haslayer(Ether):
        try:
            packet_proto = ETHER_TYPES[packet[Ether].type]
        except:
            packet_proto = packet[Ether].type

    # If packet is another standard, find protcol type by index
    else:
        try:
            packet_proto = str(packet[2]).split(" ")[0]  # Protocol: STP, ICMP, ARP,...
        except:
            packet_proto = None

    size = len(packet)

    # Determine if packet is unicast, multicast, or broadcast
    if dst_mac == "ff:ff:ff:ff:ff:ff":
        packet_type = "Broadcast"
    elif (int(dst_mac.split(":")[0], 16) & 1) == 1:
        packet_type = "Multicast"
    else:
        packet_type = "Unicast"

    # Return dict of info
    return {
        "eth_type": eth_pdu_type,
        "src": src_mac,
        "dst": dst_mac,
        "proto": packet_proto,
        "size": size,
        "cast_type": packet_type,
    }


def analyzeL3(packet):
    """Analyzes Network layer of packet"""
    # Check if the packet has IP layer
    if not packet.haslayer(IP):
        print("PDU does not have IP layer")
        return None

    # Extract IP header information
    src = packet[IP].src
    dst = packet[IP].dst
    proto = proto_table[packet[IP].proto]
    size = len(packet[IP])
    ttl = packet[IP].ttl
    version = packet[IP].version

    # Public or private ip
    src_ip_type = "Private" if isPrivate(src) else "Public"
    dst_ip_type = "Private" if isPrivate(dst) else "Public"

    # Find details about subnet mask
    if src_mask := getSubnet(
        src
    ):  # if we can get subnet mask, calculate all other info
        src_sub = isSubnetted(src, src_mask)
        src_netid = getNetId(src, src_mask)
        src_cidr = maskToCidr(src, src_mask)
        src_broadcast = getBroadcast(src, src_mask)
    else:  # if we cannot, set everything to none
        src_sub = None
        src_netid = None
        src_cidr = None
        src_broadcast = None
    if dst_mask := getSubnet(
        dst
    ):  # if we can get subnet mask, calculate all other info
        dst_sub = isSubnetted(dst, dst_mask)
        dst_netid = getNetId(dst, dst_mask)
        dst_cidr = maskToCidr(dst, dst_mask)
        dst_broadcast = getBroadcast(dst, dst_mask)
    else:  # if we cannot, set everything to none
        dst_sub = None
        dst_netid = None
        dst_cidr = None
        dst_broadcast = None

    # Return dict of info
    return {
        "src": src,
        "dst": dst,
        "proto": proto,
        "ver": version,
        "size": size,
        "ttl": ttl,
        "src_pub_priv": src_ip_type,
        "dst_pub_priv": dst_ip_type,
        "src_mask": src_mask,
        "src_sub": src_sub,
        "src_netid": src_netid,
        "src_cidr": src_cidr,
        "src_broadcast": src_broadcast,
        "dst_mask": dst_mask,
        "dst_sub": dst_sub,
        "dst_netid": dst_netid,
        "dst_cidr": dst_cidr,
        "dst_broadcast": dst_broadcast,
    }


def analyzeL4(packet):
    """Analyzes Transport Layer of packet"""
    # Checks if packet has a UDP/TCP layer
    if not (packet.haslayer(UDP) or packet.haslayer(TCP) or packet.haslayer(SCTP)):
        print("PDU does not have UDP/TCP Layer")
        return None

    # Find transport layer protocol
    proto = str(packet[2]).split(" ")[0].lower()

    # Find port and application type
    src_port = translatePort(packet.sport, proto)
    dst_port = translatePort(packet.dport, proto)

    return {"src_port": src_port, "dst_port": dst_port, "proto": proto.upper()}


def convHex(hexdump):
    """Converts a hexdump to bits (0 and 1)"""\
    # Find all bytes in the dump
    hex_bytes = re.findall(r" ([\dABCDEF]{2})", hexdump)

    # Convert hexadecimal to binary
    def hexToBin(n):
        return bin(int(n, 16))[2:].zfill(8)
    
    # Map conversion function to all bytes
    bin_bytes = map(hexToBin, hex_bytes)
    
    # Return raw bits
    return " ".join(list(bin_bytes))
