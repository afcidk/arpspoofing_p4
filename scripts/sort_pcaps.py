#!/usr/bin/env python
from scapy.all import *

PCAP_SRC = '../pacps/'

def read_all_packets(switches):
    packets = None
    for name in switches:
        if packets != None:
            packets += rdpcap('{}{}_in.pcap'.format(PCAP_SRC, name))
        else:
            packets = rdpcap('{}{}_in.pcap'.format(PCAP_SRC, name))
        packets += rdpcap('{}{}_out.pcap'.format(PCAP_SRC, name))
    return packets

def read_LP(switches):
    size = 0
    packets = read_all_packets(switches)
    for packet in packets:
        eth = packet.getlayer(Ether)
        if eth.type == 0x600 or eth.type == 0x5ff:
            size += len(packet)

    print('LP/LRP total size: {} bytes'.format(size))

def read_ARP(switches):
    size = 0
    packets = read_all_packets(switches)
    for packet in packets:
        eth = packet.getlayer(Ether)
        if eth.type == 0x806:
            size += len(packet)

    print('ARP total size: {} bytes'.format(size))


def main():
    inner_ports = ['s10-eth3','s20-eth1','s20-eth2','s30-eth4']
    edge_ports = ['s10-eth1', 's10-eth2', 's30-eth1', 's30-eth2', 's30-eth3']
    read_LP(inner_ports)
    read_ARP(inner_ports + edge_ports)

if __name__ == '__main__':
    main()
