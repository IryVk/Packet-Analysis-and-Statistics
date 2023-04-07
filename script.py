from time import sleep
from scapy.all import *
from analyze import *
from tabulate import tabulate
from datetime import datetime


count = 0  # counter to name packets
FILENAME = datetime.now().strftime('%d-%m-%Y %H-%M-%S')

# Adjust print function to also print to Log file as well as terminal
old_print = print
# NOTE: content will appear in the txt file when the script is finished
log_file = open(f"captured/captured {FILENAME}.txt", "a", encoding="utf-8")
print = lambda *args, **kw: old_print(*args, **kw) or old_print(*args, file=log_file, **kw)


def main():
    old_print("""Script will run in 5 seconds, a random packet will be captured and analyzed every minute.
To terminate script, press ctrl + c and wait for any running processes to finish.
In /captured/, you can find a log file of the output info, a pcap of the captured packets and a graphic pdf dump of each packet.
""")
    sleep(5)
    try:
        while True:
            sniff(count=1, prn=output)
            sleep(60)  # Wait one minute before capturing another packet
    # To ensure that the packet being analyzed is done before ending program
    except KeyboardInterrupt:  
        log_file.close()


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
        print("-" * 100)
        print("Layer 3 Information")
        print("-" * 100)
        print(tabulate(l3_table, tablefmt="plain"))
        print("-" * 100)

    # if packet has tcp/udp layer, get info and put it in table
    if l4 := analyzeL4(packet):
        l4_table = [
            ["Tranport Layer Protocol:", l4["proto"]],
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
        print("-" * 100)
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
            l4["proto"],
        ]
        src_desc = l4["src_port"]["desc"]

        # format desc if it's too long
        if src_desc:
            if len(src_desc) > 25:
                src_desc = src_desc[:25]
        dst_desc = l4["dst_port"]["desc"]
        if dst_desc:
            if len(dst_desc) > 25:
                dst_desc = dst_desc[:25]

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

    # Print PDU architecture
    print("-" * 100)
    print("#" * 30)
    print("#" + f"PDU {count} structure".center(28) + "#")
    print("#" * 30)
    print("-" * 100)

    print("Bits")
    bits = convHex(hexdump(packet, True)) # Convert hexdump of packet to binary
    l1_head = ["#", "Layer Name", "Bits"]
    l1_struct = [[1, "Physical Layer", bits[:60] + "..."]]  # Print only part of the bits to terminal because it's too long
    print(tabulate(l1_struct, headers=l1_head, tablefmt="rounded_grid"))
    print("-" * 100)

    print("Ethernet Frame")
    l2_head = ["#", "Layer Name" ,"Destination MAC", "Source MAC", "Ethertype/Length", "Packet", "FCS"]
    # If packet is Ethernet II print ethertype, else print length
    l2_struct = [[2, "Data Link Layer", l2["dst"], l2["src"], f"Ethertype {l2['proto']}" if packet.haslayer(Ether) else f"Length {len(packet)}", "", ""]]
    print(tabulate(l2_struct, headers=l2_head, tablefmt="rounded_grid"))
    print("-" * 100)

    if l3:
        print("IP Packet")
        l3_head = ["#", "Layer Name" ,"Destination IP", "Source IP", "Protocol", "...", "Segment"]
        l3_struct = [[3, "Network Layer", l3["dst"], l3["src"], l3["proto"], "", ""]]
        print(tabulate(l3_struct, headers=l3_head, tablefmt="rounded_grid"))
        print("-" * 100)

    if l4:
        print("Segment")
        l4_head = ["#", "Layer Name" ,"Destination Port", "Source Port", "...", "Data"]
        l4_struct = [[4, "Transport Layer", l4["dst_port"]["port"], l4["src_port"]["port"], "", ""]]
        print(tabulate(l4_struct, headers=l4_head, tablefmt="rounded_grid"))
        print("-" * 100)


    # Save captured packets in a pcap file
    wrpcap(f"captured/captured {FILENAME}.pcap", packet, append=True)
    # Make a pdf of packet details
    packet.pdfdump(f"captured/packet_{count} {FILENAME}.pdf",layer_shift=1)
    


if __name__ == "__main__":
    main()
