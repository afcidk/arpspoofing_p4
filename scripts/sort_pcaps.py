#!/usr/bin/env python
from scapy.all import *
import matplotlib.pyplot as plt
import numpy as np
import os

def preprocess(switches, src):
    for s in switches:
        print('{1}{0}.pcap'.format(s, src))
        os.system('mergecap -a {1}{0}_in.pcap {1}{0}_out.pcap -w {1}{0}.pcap -F libpcap'.format(s, src))

def read_all_packets(switches, PCAP_SRC):
    packets = None
    for name in switches:
        if packets == None:
            packets = rdpcap('{}{}.pcap'.format(PCAP_SRC, name))
        else:
            packets += rdpcap('{}{}.pcap'.format(PCAP_SRC, name))

    return packets

def read_LP(switches, src):
    size = 0
    packets = read_all_packets(switches, src)
    for packet in packets:
        eth = packet.getlayer(Ether)
        if eth.type == 0x600 or eth.type == 0x5ff:
            size += len(packet)

    print('LP/LRP total size: {} bytes'.format(size))
    return size

def read_ARP(switches, src):
    size = 0
    packets = read_all_packets(switches,src) 
    for packet in packets:
        eth = packet.getlayer(Ether)
        if eth.type == 0x806:
            size += len(packet)

    print('ARP total size: {} bytes'.format(size))
    return size

def read_all(switches, src):
    size = 0
    packets = read_all_packets(switches, src)
    for packet in packets:
        size += len(packet)

    print("Total size: {} bytes".format(size))
    return size

def main():
    PCAP_SRC = '../pcaps/'
    all_switches = ['s10-eth1', 's10-eth2', 's10-eth3', 's20-eth1', 's20-eth2', 's30-eth1', 's30-eth2', 's30-eth3', 's30-eth4']
    inner_ports = ['s10-eth3','s20-eth1','s20-eth2','s30-eth4']
    edge_ports = ['s10-eth1', 's10-eth2', 's30-eth1', 's30-eth2', 's30-eth3']
    host_ports = ['h10-eth0', 'h20-eth0', 'h30-eth0', 'h40-eth0']
    controller = ['packet_in']

    preprocess(all_switches, PCAP_SRC)
    print("###### Inner ports ######")
    read_LP(inner_ports, PCAP_SRC)
    read_all(inner_ports, PCAP_SRC)

    print("###### Inner ports + Edge ports ######")
    read_ARP(inner_ports + edge_ports, '../pcaps/')
    read_all(inner_ports + edge_ports, '../pcaps/')

    print("###### Host ports ######")
    read_LP(host_ports , PCAP_SRC)
    read_ARP(host_ports, PCAP_SRC)
    read_all(host_ports, PCAP_SRC)

    print("###### Packet in ######")
    read_LP(controller,  PCAP_SRC)
    read_ARP(controller, PCAP_SRC)
    read_all(controller, PCAP_SRC)


if __name__ == '__main__':
    main()
