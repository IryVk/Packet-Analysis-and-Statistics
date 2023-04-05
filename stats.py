import matplotlib.pyplot as plt
import numpy as np

from scapy.all import *


# Global Variables
SAMPLE = 500
CONTROL = ["STP", "DTP", "ARP", "ICMP", "DNS", "DHCP", "CDP"]
CNT = 0
DATA = 0
PDUS = []


def count(packet):
    """Count number of control and data PDUs"""
    global CNT, DATA, CONTROL

    if packet.haslayer(UDP):
        # If packet is DNS
        if packet[UDP].sport == 53 or packet[UDP].dport == 53:
            CNT += 1
            PDUS.append("DNS")
            return
        # If packet is DHCP
        elif packet[UDP].sport == 67 or packet[UDP].sport == 68 or packet[UDP].dport == 67 or packet[UDP].dport == 68:
            CNT += 1
            PDUS.append("DHCP")
            return
        
    proto = str(packet[2]).split(" ")[0]
    #print(proto)
    PDUS.append(proto)
    if proto in CONTROL:
        CNT += 1
    else:
        DATA += 1


def capture():
    """Capture packets"""
    global SAMPLE
    sniff(count=SAMPLE, prn=count)


def piePlot(x, y):
    """Make a piechart of the data"""
    pie = np.array([x, y])
    plt.title("Ratio of Data to Control PDUs")
    plt.pie(pie, labels=[f"Data ({x})",f"Control ({y})"], explode=[0,0.2])
    plt.legend(title="PDUs:")
    plt.show() 


def barPlot():
    """Make a bar graph of all PDUs captured"""
    elements = []
    counter = []
    for pdu in PDUS:
        if pdu not in elements:
            counter.append(1)
            elements.append(pdu)
        else:
            counter[elements.index(pdu)] += 1
    plt.bar(elements, counter)
    plt.title("Total number of each PDU")
    plt.xlabel("PDUs")
    plt.ylabel("Count")
    plt.show()


def main():
    capture()
    piePlot(DATA, CNT)
    barPlot()
    print(f"Ratio of Control to Data PDUs: {CNT/DATA}")


if __name__ == "__main__":
    main()


