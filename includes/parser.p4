#ifndef __PARSER__
#define __PARSER__

#include "headers.p4"

// Parser
parser basic_tutor_switch_parser(
    packet_in packet,
    out headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    state start {
        transition select(standard_metadata.ingress_port){
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
			TYPE_ARP: parse_arp;
            default: accept;
        }
    }

	state parse_arp {
		packet.extract(hdr.arp);
		hdr.arp.setValid();
		transition accept;
	}

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
		hdr.ipv4.setValid();
        transition select(hdr.ipv4.protocol){
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
		hdr.tcp.setValid();
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
		transition select(hdr.udp.srcPort) {
			67: parse_dhcp;
			68: parse_dhcp;
			default: accept;
		}
    }

	state parse_dhcp {
		packet.extract(hdr.dhcp);
		transition accept;
	}
}

// Deparser
control basic_tutor_switch_deparser(
    packet_out packet,
    in headers_t hdr
){
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
		packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
		packet.emit(hdr.dhcp);
    }
}

#endif
