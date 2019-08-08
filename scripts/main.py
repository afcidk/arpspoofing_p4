#!/usr/bin/env python
from sort_pcaps import *
import matplotlib.pyplot as plt
import numpy as np

# Setup pcap srcs
PCAP_SRC1 = '../pcaps3/' 
PCAP_SRC2 = '../pcaps2/'
PCAP_SRC3 = '../pcaps/'

def analyze(ports, func, action_name, method_names):
    print("Running {}".format(action_name))
    x = np.arange(3)
    plt.bar(x, [func(ports, PCAP_SRC1), func(ports, PCAP_SRC2), func(ports, PCAP_SRC3)])
    plt.xticks(x, method_names)
    plt.savefig(action_name + '.png')
    plt.clf()

def main():
    inner_ports = ['s10-eth3','s20-eth1','s20-eth2','s30-eth4']
    edge_ports = ['s10-eth1', 's10-eth2', 's30-eth1', 's30-eth2', 's30-eth3']
    host_ports = ['h10-eth0', 'h20-eth0', 'h30-eth0', 'h40-eth0']
    controller = ['packet_in']
    all_switches = ['s10-eth1', 's10-eth2', 's10-eth3', 's20-eth1', 's20-eth2', 's30-eth1', 's30-eth2', 's30-eth3', 's30-eth4']
    preprocess(all_switches, PCAP_SRC1)

    analyze(inner_ports, read_ARP, "ARP_inner_ports", ["DHCP", "LP", "P4"])
    analyze(inner_ports, read_LP, "LP_inner_ports", ["DHCP", "LP", "P4"])
    analyze(controller, read_all, "packetIn_controller", ["DHCP", "LP", "P4"])
    analyze(controller, read_ARP, "ARP_controller", ["DHCP", "LP", "P4"])

if __name__ == '__main__':
    main()


