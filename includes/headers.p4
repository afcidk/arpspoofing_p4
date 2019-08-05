#ifndef __HEADERS__
#define __HEADERS__

#include "codex/enum.p4"
#include "codex/l2.p4"
#include "codex/l3.p4"
#include "codex/l4.p4" 
#include "codex/l567.p4"

#define CPU_PORT 255
#define MCAST_BASE 0x70

// packet in 
@controller_header("packet_in")
header packet_in_header_t {
    bit<16>  ingress_port;
}

// packet out 
@controller_header("packet_out")
header packet_out_header_t {
    bit<16>  egress_port;
	bit<16>   mcast_grp;
}

// header struct for packet
struct headers_t {
    packet_out_header_t     packet_out;
    packet_in_header_t      packet_in;
    ethernet_t              ethernet;
	arp_t					arp;
    ipv4_t                  ipv4;
    tcp_t                   tcp;
    udp_t                   udp;
	dhcp_t					dhcp;
}

// digest
struct arp_request_digest_t {
	bit<16> ingress_port;
	bit<32> dstIPAddr;
	bit<32> srcIPAddr;
}

// metadata inside switch pipeline
struct metadata_t {

}

#endif
