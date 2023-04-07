import matplotlib.pyplot as plt
import numpy as np
import os

from scapy.all import *
from datetime import datetime


# IMPORTANT: If script takes a while to finish running that's normal, please be patient
# Let script run until graphs are displayed
# Depending on the network, it might take a while to collect the 500 PDU sample size

# Global Variables
SAMPLE = 500
CONTROL = ["STP", "DTP", "ARP", "ICMP", "DNS", "DHCP", "CDP"]
CNT = 0  # Counter for control PDUs
DATA = 0  # Counter for data PDUs
PDUS = []  # List to store PDU protocols
FILENAME = datetime.now().strftime('%d-%m-%Y %H-%M-%S')


def main():
    print(f"""Script is now running, please wait for the sample size of {SAMPLE} packets to be collected.
Please be patient, it might take some time depending on your device's network traffic.
In /statistics/, you can find a pcap of the sample collected, and the graphs displayed""")
    capture()
    piePlot(DATA, CNT)
    barPlot()
    print(f"Ratio of Control to Data PDUs: {f'{(CNT/DATA):.4f}'}")


def capture():
    """Capture packets"""
    global SAMPLE
    sniff(count=SAMPLE, prn=count)
        


def count(packet):
    """Count number of control and data PDUs"""
    # Save packets in a pcap file
    wrpcap(f"statistics/Sample {FILENAME}.pcap", packet, append=True)

    global DATA, CONTROL, CNT
    # Iterate over CONTROL PDUs list and if they are present in PDU, increase count of control and return
    for item in CONTROL:
        if item in packet.payload:
            CNT += 1
            PDUS.append(item)
            return
    # Else increment data count
    DATA += 1
    


def piePlot(x, y):
    """Make a piechart of the data"""
    pie = np.array([x, y])
    plt.title("Ratio of Data to Control PDUs")
    plt.pie(pie, labels=[f"Data ({x})", f"Control ({y})"], explode=[0, 0.2])
    plt.legend(title="PDUs:")
    # Save graph to file
    plt.savefig(f"statistics\Sample {FILENAME}_ratio.png")
    # Show graph
    plt.show()


def barPlot():
    """Bar Graph of Control PDUs Captured"""
    elements = []
    counter = []
    for pdu in PDUS:
        if pdu not in elements:
            counter.append(1)
            elements.append(pdu)
        else:
            counter[elements.index(pdu)] += 1
    plt.bar(elements, counter)
    plt.title("Control PDUs Captured")
    plt.xlabel("PDUs")
    plt.ylabel("Count")
    # Save graph to file
    plt.savefig(f"statistics\Sample {FILENAME}_cntrl_pdus.png")
    # Show graph
    plt.show()


if __name__ == "__main__":
    main()
