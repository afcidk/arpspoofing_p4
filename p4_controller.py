#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse, grpc, os, sys
import scapy
import json
import socket, struct
import threading  # One thread per switch
from time import sleep
from scapy.all import *

# set our lib path
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
        '../../../../utils/'))

BCAST = "ff:ff:ff:ff:ff:ff"
DHCP_SWITCH = "h50"
DHCP_PORT = 3
ETHERTYPE_ARP = 0x0806
ETHERTYPE_LP  = 0x5ff
ETHERTYPE_LRP = 0x600
MCAST_BASE = 0x70
ip_mac_table = {}
mac_port_sw_table = {}
pending_entry = {} # key: (switch,MAC), value: inPort
delayed_packetIn = {}
installed_pair = [] # value: (src,dst)
switch = None

# And then we import
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def install_bidirection_entry(p4info_helper, sw, match1, match2):
    print('1.{}+{} => {}'.format(match1[0], match1[1].encode('hex'), match2[1].encode('hex')))
    entry = p4info_helper.buildTableEntry(
            table_name = "basic_tutorial_ingress.mac.mac_table",
            match_fields = {
                "hdr.ethernet.dstAddr": match1[0],
                "standard_metadata.ingress_port": match1[1]
            },
            action_name = "basic_tutorial_ingress.mac.forward",
            action_params = {"outPort": match2[1]}
        )
    try:
        sw.WriteTableEntry(entry)
    except Exception as e:
        print(e)

    print('2.{}+{} => {}'.format(match2[0], match2[1].encode('hex'), match1[1].encode('hex')))
    entry = p4info_helper.buildTableEntry(
            table_name = "basic_tutorial_ingress.mac.mac_table",
            match_fields = {
                "hdr.ethernet.dstAddr": match2[0],
                "standard_metadata.ingress_port": match2[1]
            },
            action_name = "basic_tutorial_ingress.mac.forward",
            action_params = {"outPort": match1[1]}
        )
    try:
        sw.WriteTableEntry(entry)
    except Exception as e:
        print(e)


def install_LP_packetIn(p4info_helper, sw_s):
    for sw in sw_s:
        entry = p4info_helper.buildTableEntry(
            table_name = "basic_tutorial_ingress.lp.lp_table",
            match_fields = {
                "hdr.ethernet.etherType": ETHERTYPE_LP
            },
            action_name = "basic_tutorial_ingress.lp.send_to_cpu",
            action_params = {}
        )
        sw.WriteTableEntry(entry)

        entry = p4info_helper.buildTableEntry(
            table_name = "basic_tutorial_ingress.lp.lp_table",
            match_fields = {
                "hdr.ethernet.etherType": ETHERTYPE_LRP
            },
            action_name = "basic_tutorial_ingress.lp.send_to_cpu",
            action_params = {}
        )
        sw.WriteTableEntry(entry)

def install_arp_reply_drop(p4info_helper, sw_s):
    for sw in sw_s:
        entry = p4info_helper.buildTableEntry(
            table_name = "basic_tutorial_ingress.arp.arp_table",
            match_fields = {
                "hdr.ethernet.etherType": ETHERTYPE_ARP,
                "hdr.arp.oper": 2 # 2 for reply
            },
            action_name = "basic_tutorial_ingress.arp._drop",
            action_params = {}
        )
        sw.WriteTableEntry(entry)

def install_dhcp_packetIn(p4info_helper, sw):
    entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress.dhcp.dhcp_table",
        match_fields = {
            "standard_metadata.ingress_port": DHCP_PORT,     
            "hdr.udp.srcPort": 67, # DHCP discover/request
            "hdr.udp.dstPort": 68
        },
        action_name = "basic_tutorial_ingress.dhcp.send_to_cpu",
        action_params = {}
    )
    sw.WriteTableEntry(entry)

def install_arp_packetIn(p4info_helper, sw_s):
    for sw in sw_s:
        entry = p4info_helper.buildTableEntry(
            table_name = "basic_tutorial_ingress.arp.arp_table",
            match_fields = {
                "hdr.ethernet.etherType": ETHERTYPE_ARP,
                "hdr.arp.oper": 1 # 1 for request
            },
            action_name = "basic_tutorial_ingress.arp.send_to_cpu",
            action_params = {}
        )
        sw.WriteTableEntry(entry)

def install_dhcp_drop(p4info_helper, sw_s, sw_rs, port_map):
    for sw,name in zip(sw_s, sw_rs):
        for port in port_map[name].values():
            if name == "s30" and port == DHCP_PORT: continue

            entry = p4info_helper.buildTableEntry(
                table_name = "basic_tutorial_ingress.dhcp.dhcp_table",
                match_fields = {
                    "standard_metadata.ingress_port": port,
                    "hdr.udp.srcPort": 67, # DHCP discover/request
                    "hdr.udp.dstPort": 68
                },
                action_name = "basic_tutorial_ingress.dhcp._drop",
                action_params = {}
            )
            sw.WriteTableEntry(entry)

def install_dhcp_packetIn13(p4info_helper, sw_s, sw_rs, port_map):
    for sw,name in zip(sw_s, sw_rs):
        for port in port_map[name].values():
            entry = p4info_helper.buildTableEntry(
                table_name = "basic_tutorial_ingress.dhcp.dhcp_table",
                match_fields = {
                    "standard_metadata.ingress_port": port,
                    "hdr.udp.srcPort": 68, # DHCP offer/ack
                    "hdr.udp.dstPort": 67
                },
                action_name = "basic_tutorial_ingress.dhcp.send_to_cpu",
                action_params = {}
            )
            sw.WriteTableEntry(entry)

def printGrpcError(e):
    print "gRPC Error: ", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    # detail about sys.exc_info - https://docs.python.org/2/library/sys.html#sys.exc_info
    traceback = sys.exc_info()[2]
    print "[%s:%s]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def byte_pbyte(data):
    # check if there are multiple bytes
    if len(str(data)) > 1:
        # make list all bytes given
        msg = list(data)
        # mark which item is being converted
        s = 0
        for u in msg:
            # convert byte to ascii, then encode ascii to get byte number
            u = str(u).encode("hex")
            # make byte printable by canceling \x
            u = "\\x"+u
            # apply coverted byte to byte list
            msg[s] = u
            s = s + 1
        msg = "".join(msg)
    else:
        msg = data
        # convert byte to ascii, then encode ascii to get byte number
        msg = str(msg).encode("hex")
        # make byte printable by canceling \x
        msg = "\\x"+msg
    # return printable byte
    return msg

def prettify(mac_string):
    return ':'.join('%02x' % ord(b) for b in mac_string)

def get_port_map(nodes, links):
    port_map_raw = {l: [] for l in nodes}
    for link in links:
        if link[0] in nodes:
            port_map_raw[link[0]].append(link[1])
        if link[1] in nodes:
            port_map_raw[link[1]].append(link[0])

    port_map = {l: {} for l in nodes}
    for key in port_map_raw.keys():
        for idx,e in enumerate(sorted(port_map_raw[key])):
            port_map[key].update({e:idx+1})

    return port_map

def read_topology(path):
    with open(path, 'r') as f:
        c = json.load(f)
        hosts = c[u'hosts']
        switches = sorted(c[u'switches'].keys())
        links = c[u'links']
        port_map = get_port_map(switches, links)
        # Strange, why need to sort????
        return hosts, switches, links, port_map

def gen_arp_reply(p4info_helper, packet, rev=False):
    src_ip = packet.getlayer(ARP).psrc
    src_mac = packet.getlayer(ARP).hwsrc
    if src_ip not in ip_mac_table or \
       src_mac != ip_mac_table[src_ip]:
           return False
    
    request_ip = packet.getlayer(ARP).pdst
    if request_ip not in ip_mac_table:
        return False
    request_mac = ip_mac_table[request_ip]

    if rev:
        packet.getlayer(Ether).dst = request_mac
        packet.getlayer(Ether).src = src_mac
        packet.getlayer(ARP).hwdst = request_mac
        packet.getlayer(ARP).pdst = request_ip
        packet.getlayer(ARP).hwsrc = src_mac
        packet.getlayer(ARP).psrc = src_ip
        packet.getlayer(ARP).op = ARP.who_has
    else:
        packet.getlayer(ARP).op = ARP.is_at
        packet.getlayer(Ether).dst = src_mac
        packet.getlayer(Ether).src = request_mac
        packet.getlayer(ARP).hwdst = src_mac
        packet.getlayer(ARP).pdst = src_ip
        packet.getlayer(ARP).hwsrc = request_mac
        packet.getlayer(ARP).psrc = request_ip
    return packet

def gen_LPlike(srcMAC, dstMAC, type):
    return Ether(
        src=srcMAC, dst=dstMAC,
        type=type
    )

def handle_ARP_packetIn(p4info_helper, sw, packetIn):
    packet = packetIn.packet.payload
    inport = packetIn.packet.metadata[0].value
    pkt = gen_arp_reply(p4info_helper, Ether(_pkt=packet)) 
    if pkt == False: return 

    # Send back ARP reply
    packet_out = p4info_helper.buildPacketOut(
        payload = str(pkt),
        metadata = {
            1: inport,
            2: inport
        }
    )
    src = pkt.getlayer(Ether).src
    dst = pkt.getlayer(Ether).dst
    delayed_packetIn[(src,dst)] = packet_out

    # Broadcast LP, check if dst edge switch is the same as current edge switch
    inport_t = int(inport.encode('hex'), 16) + MCAST_BASE
    orig_pkt = Ether(_pkt=packet)
    dstIP = orig_pkt.getlayer(ARP).pdst
    srcMAC = orig_pkt.getlayer(Ether).src
    dstMAC = ip_mac_table[dstIP]
    outport = mac_port_sw_table[dstMAC][0]
    pkt = gen_LPlike(srcMAC, dstMAC, type=ETHERTYPE_LP)

    if mac_port_sw_table[dstMAC][1] == sw:
        print('Same edge switch, no need to send LP')
        sw.PacketOut(delayed_packetIn[(dstMAC, srcMAC)])
        del delayed_packetIn[(dstMAC,srcMAC)]
        if (srcMAC, dstMAC) not in installed_pair:
            installed_pair.append((srcMAC,dstMAC))
            installed_pair.append((dstMAC,srcMAC))
            install_bidirection_entry(p4info_helper, sw, (srcMAC,outport), (dstMAC,inport))
    else:
        # record pending entry
        # check if (srcMAC,dstMAC) recorded before
        if (srcMAC,dstMAC) not in installed_pair:
            pending_entry[(sw, dstMAC)] = inport
            print("ARP mgid = {}, inport = {}".format(inport_t, inport_t-MCAST_BASE))

            installed_pair.append((srcMAC,dstMAC))
            installed_pair.append((dstMAC,srcMAC))

            packet_out = p4info_helper.buildPacketOut(
                payload = str(pkt),
                metadata = {
                    1: inport,
                    2: chr(inport_t/0xff)+chr(inport_t%0xff)
                }
            )
            sw.PacketOut(packet_out)
        else:
            sw.PacketOut(delayed_packetIn[(dstMAC, srcMAC)])
            del delayed_packetIn[(dstMAC,srcMAC)]


# handle offer, ack
def handle_dhcp_op2(p4info_helper, sw, packetIn):
    print("DHCP op 2, send packetout to src host")
    packet = packetIn.packet.payload
    inport = packetIn.packet.metadata[0].value
    pkt = Ether(_pkt=packet)
    options = pkt.getlayer(DHCP).options
    ip = pkt.getlayer(BOOTP).yiaddr
    MAC = pkt.getlayer(Ether).dst

    # ACK
    for o in options:
        if o[0] == 'message-type' and o[1] == 5:
            ip_mac_table[ip] = MAC

    if MAC not in mac_port_sw_table: return 
    inport, sw = mac_port_sw_table[MAC]

    packet_out = p4info_helper.buildPacketOut(payload = packetIn.packet.payload, metadata = {1:inport, 2:inport})
    sw.PacketOut(packet_out)
    #print(ip_mac_table)
    print(mac_port_sw_table)

# handle discover, request
def handle_dhcp_op1(p4info_helper, sw, packetIn):
    print("DHCP op 1, send packetout to server")
    packet = packetIn.packet.payload
    inport = packetIn.packet.metadata[0].value
    pkt = Ether(_pkt=packet)
    MAC = pkt.getlayer(Ether).src

    mac_port_sw_table[MAC] = (inport,sw)
    packet_out = p4info_helper.buildPacketOut(payload = packetIn.packet.payload, metadata = {1:'\000\003', 2:'\000\003'})
    switch[2].PacketOut(packet_out)

def handle_LP_packetIn(p4info_helper, sw, packetIn):
    pkt = Ether(_pkt=packetIn.packet.payload)
    dst = pkt.getlayer(Ether).dst
    src = pkt.getlayer(Ether).src
    inport = packetIn.packet.metadata[0].value
    if pkt.getlayer(Ether).type == ETHERTYPE_LP:
        print('Is LP')
        if sw == mac_port_sw_table[dst][1]:
            print('LP Arrived edge switch, should send LRP')
            outport = mac_port_sw_table[dst][0]
            outport_t = int(outport.encode('hex'), 16) + MCAST_BASE
            LRP_pkt = Ether(src=src, dst=dst, type=ETHERTYPE_LRP)
            packet_out = p4info_helper.buildPacketOut(
                payload = str(LRP_pkt),
                metadata = {
                    1: outport,
                    2: chr(outport_t/0xff)+chr(outport_t%0xff)
                }
            )
            sw.PacketOut(packet_out)
            install_bidirection_entry(p4info_helper, sw, (src,outport), (dst,inport))
        else:
            inport_t = int(inport.encode('hex'), 16) + MCAST_BASE
            print('Continue packetOut multicast, inport: {}'.format(inport))
            pending_entry[(sw, dst)] = inport
            packet_out = p4info_helper.buildPacketOut(
                payload = str(pkt),
                metadata = {
                    1: inport,
                    2: chr(inport_t/0xff)+chr(inport_t%0xff)
                }
            )
            sw.PacketOut(packet_out)

    elif pkt.getlayer(Ether).type == ETHERTYPE_LRP:
        inport = pending_entry[(sw, dst)]
        outport = packetIn.packet.metadata[0].value
        install_bidirection_entry(p4info_helper, sw, (src,outport), (dst,inport))
        print('Is LRP')
        if sw == mac_port_sw_table[src][1]:
            print('LRP arrived edge switch, stop, packetOut arp reply')
            sw.PacketOut(delayed_packetIn[(dst, src)])
            del delayed_packetIn[(dst,src)]
        else:
            inport = packetIn.packet.metadata[0].value
            inport_t = int(inport.encode('hex'), 16) + MCAST_BASE
            print('LRP Continue packetOut multicast, inport: {}'.format(inport))
            pending_entry[(sw, dst)] = inport
            packet_out = p4info_helper.buildPacketOut(
                payload = str(pkt),
                metadata = {
                    1: inport,
                    2: chr(inport_t/0xff)+chr(inport_t%0xff)
                }
            )
            sw.PacketOut(packet_out)

def handle_packetIn(p4info_helper, sw):
    packetIn = sw.PacketIn()
    if packetIn.WhichOneof('update') == 'packet':
        pkt = Ether(_pkt=packetIn.packet.payload)
        if DHCP in pkt:
            print("DHCP packetIn")
            if pkt.getlayer(BOOTP).op == 1:
                handle_dhcp_op1(p4info_helper, sw, packetIn)
            else:
                handle_dhcp_op2(p4info_helper, sw, packetIn)
        elif ARP in pkt:
            print("ARP packetin")
            handle_ARP_packetIn(p4info_helper, sw, packetIn)
        else:
            handle_LP_packetIn(p4info_helper, sw, packetIn)

def build_switch_connection(p4info_helper, switch_raw, bmv2_file_path, port_map):
    all_switch = []
    for idx,sw in enumerate(switch_raw):
        t_sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=sw,
            address='127.0.0.1:{}'.format(50051+idx),
            device_id=idx,
            proto_dump_file="logs/{}-runtime-requests.txt".format(sw))

        print(t_sw, sw)
        t_sw.MasterArbitrationUpdate()
        t_sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForardingPipelineConfig on {}".format(sw))
        build_MC_group(p4info_helper, len(port_map[sw]), t_sw)
        all_switch.append(t_sw)
    return all_switch

def build_MC_group(p4info_helper, length, sw):
    replicas = {x+1:x+1 for x in range(length)}

    # Multicast
    for idx in range(1,length+1):
        del replicas[idx]
        entry = p4info_helper.buildMCEntry(
            mc_group_id = idx+MCAST_BASE,
            replicas = replicas
        )
        replicas.update({idx:idx})
        sw.WritePRE(mc_group = entry)

    # Unicast
    for idx in range(1, length+1):
        entry = p4info_helper.buildMCEntry(
            mc_group_id = idx,
            replicas = {idx: idx}
        )
        sw.WritePRE(mc_group = entry)

def packetIn_task(p4info_helper, sw, name):
    while True:
        handle_packetIn(p4info_helper, sw)

def main(p4info_file_path, bmv2_file_path, topology_path):
    global switch
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    hosts, switch_raw, links, port_map = read_topology(topology_path)

    threads = []
    try:
        switch = build_switch_connection(p4info_helper, switch_raw, bmv2_file_path, port_map)
        install_dhcp_packetIn(p4info_helper, switch[2])
        install_dhcp_drop(p4info_helper, switch, switch_raw, port_map)
        install_dhcp_packetIn13(p4info_helper, switch, switch_raw, port_map)
        install_arp_packetIn(p4info_helper, switch)
        install_arp_reply_drop(p4info_helper, switch)
        install_LP_packetIn(p4info_helper, switch)

        for sw,name in zip(switch, switch_raw):
            task = threading.Thread( target = packetIn_task, args = (p4info_helper, sw, name, ), name=name)
            threads.append(task)
            task.start()

        for t in threads:
            t.join()

    except KeyboardInterrupt:
        # using ctrl + c to exit
        print "Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)


    # Then close all the connections
    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    """ Simple P4 Controller
        Args:
            p4info:     指定 P4 Program 編譯產生的 p4info (PI 制定之格式、給予 controller 讀取)
            bmv2-json:  指定 P4 Program 編譯產生的 json 格式，依據 backend 不同，而有不同的檔案格式
            topology: topology
     """

    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    # Specified result which compile from P4 program
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
            type=str, action="store", required=False,
            default="./simple.p4info")
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
            type=str, action="store", required=False,
            default="./simple.json")
    parser.add_argument('--topology', help='Topology',
            type=str, action="store", required=True,
            default="./topology.json")
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nPlease compile the target P4 program first." % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nPlease compile the target P4 program first." % args.bmv2_json
        parser.exit(1)

    # Pass argument into main function
    main(args.p4info, args.bmv2_json, args.topology)
