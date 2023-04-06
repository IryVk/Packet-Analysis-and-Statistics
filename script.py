from time import sleep
from scapy.all import *
from analyze import *
from tabulate import tabulate


count = 0  # counter to name packets


def main():
    while True:
        sniff(count=1, prn=output)
        sleep(60)  # Wait one minute before capturing another packet


def output(packet):

    # counter for packet number
    global count
    count += 1

    # Get layer 2 info
    l2 = analyzeL2(packet)
    # Put info into table
    l2_table = [
        ["Ethernet Standard:", l2["eth_type"]],
        ["Source MAC Address:", l2["src"]],
        ["Destination MAC Address:", l2["dst"]],
        ["Protocol:", l2["proto"]],
    ]

    # format prints
    print("#" * 30)
    print("#" + f"Packet {count} ({l2['cast_type']})".center(28) + "#")
    print("#" * 30)
    print("-" * 100)
    print("Layer 2 Information")
    print("-" * 100)
    print(tabulate(l2_table, tablefmt="plain"))
    print("-" * 100)

    # if packet has ip layer, get info and put it in table
    if l3 := analyzeL3(packet):
        l3_table = [
            ["IP Version:", f"IPv{l3['ver']}"],
            ["Source IP Address:", l3["src"] + " " + f"({l3['src_pub_priv']})"],
            ["Subnetted:", l3["src_sub"]],
            ["Network ID:", l3["src_netid"]],
            ["CIDR:", l3["src_cidr"]],
            ["Broadcast:", l3["src_broadcast"]],
            ["Destination IP Address:", l3["dst"] + " " + f"({l3['dst_pub_priv']})"],
            ["Subnetted:", l3["dst_sub"]],
            ["Network ID:", l3["dst_netid"]],
            ["CIDR:", l3["dst_cidr"]],
            ["Broadcast:", l3["dst_broadcast"]],
            ["Protocol:", l3["proto"]],
        ]

        # format prints
        print("Layer 3 Information")
        print("-" * 100)
        print(tabulate(l3_table, tablefmt="plain"))
        print("-" * 100)

    # if packet has tcp/udp layer, get info and put it in table
    if l4 := analyzeL4(packet):
        l4_table = [
            [
                "Source Port:",
                f"{l4['src_port']['port']} ({l4['src_port']['type']}) ({l4['src_port']['name']}: {l4['src_port']['desc']})",
            ],
            [
                "Destination Port:",
                f"{l4['dst_port']['port']} ({l4['dst_port']['type']}) ({l4['dst_port']['name']}: {l4['dst_port']['desc']})",
            ],
        ]

        # Format prints
        print("Layer 4 Information")
        print("-" * 100)
        print(tabulate(l4_table, tablefmt="plain"))
        print("-" * 100)

    # Headers for table
    osi_headers = ["#", "OSI Model Layers", "PDU", "Address Type", "Protocols"]
    # Osi table
    osi_table = [
        [
            7,
            "Application Layer\nN/A for this PDU",
            "Data",
            "Port Number",
            "HTTPS/FTP/DHCP/...",
        ],
        [6, "Presentation"],
        [5, "Session Layer"],
        [
            4,
            "Transport Layer\nN/A for this PDU",
            "Segment",
            "Port Number",
            "TCP/UDP/SCTP",
        ],
        [3, "Network Layer\nN/A for this PDU", "Packet", "IP Address", "IPv4/IPv6"],
        [
            2,
            "Data Link Layer",
            "Frame",
            f"MAC Address\nSource: {l2['src']}\nDestination: {l2['dst']}",
            l2["eth_type"],
        ],
        [1, "Physical Layer", "Bit", "Signaling", l2["eth_type"]],
    ]

    # If packet has ip layer, put info in osi table
    if l3:
        osi_table[4] = [
            3,
            "Network Layer",
            "Packet",
            f"IP Address\nSourse: {l3['src']}\nDestination: {l3['dst']}",
            f"IPv{l3['ver']}",
        ]
    # If packet has tcp/udp layer, put info in osi table
    if l4:
        osi_table[3] = [
            4,
            "Transport Layer",
            "Segment",
            f"Port Number\nSource: {l4['src_port']['port']}\nDestination: {l4['dst_port']['port']}",
            l3["proto"],
        ]
        src_desc = l4["src_port"]["desc"]
        # format desc if it's too long
        if src_desc:
            if len(src_desc) > 30:
                src_desc = src_desc[:30]
        dst_desc = l4["dst_port"]["desc"]
        if dst_desc:
            if len(dst_desc) > 30:
                dst_desc = dst_desc[:30]
        osi_table[0] = [
            7,
            "Application Layer",
            "Data",
            f"Port Number\nSource: {l4['src_port']['port']}\nDestination: {l4['dst_port']['port']}",
            f"*\n({l4['src_port']['type']}) ({l4['src_port']['name']}: {f'{src_desc}'})\n({l4['dst_port']['type']}) ({l4['dst_port']['name']}: {f'{dst_desc}'})",
        ]

    # Print table
    print("#" * 50)
    print("#" + f"OSI Model".center(48) + "#")
    print("#" * 50)
    print(tabulate(osi_table, headers=osi_headers, tablefmt="fancy_grid"))


if __name__ == "__main__":
    main()
