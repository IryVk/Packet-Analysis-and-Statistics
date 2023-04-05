import matplotlib.pyplot as plt
import numpy as np

from scapy.all import *


# Global Variables
SAMPLE = 500
CONTROL = ["STP", "DTP", "ARP", "ICMP", "DNS", "DHCP"]
CNT = 0
DATA = 0
PDUS = []


def count(packet):
    """Count number of control and data PDUs"""
    global CNT, DATA, CONTROL
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


def plot(x, y):
    """Make a piechart of the data"""
    pie = np.array([x, y])
    plt.title("Ratio of Data to Control PDUs")
    plt.pie(pie, labels=[f"Data ({x})",f"Control ({y})"], explode=[0,0.2])
    plt.legend(title="PDUs:")
    plt.show() 


def main():
    capture()
    plot(DATA, CNT)
    print(f"Ratio of Control to Data PDUs: {CNT/DATA}")


if __name__ == "__main__":
    main()


