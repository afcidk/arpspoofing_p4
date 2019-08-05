#ifndef __ARP__
#define __ARP__

control arp (
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
	action send_to_cpu() {
		standard_metadata.egress_spec = CPU_PORT;
		hdr.packet_in.setValid();
		hdr.packet_in.ingress_port = (bit<16>)standard_metadata.ingress_port;
	}

	action _drop() {
		mark_to_drop(standard_metadata);
	}

    table arp_table {
        key = {
			hdr.ethernet.etherType: exact;
			hdr.arp.oper: exact;
        }
        actions = {
			send_to_cpu;
			_drop;
        }
        size = 1024;
        default_action = _drop();
    }

    apply {
		if (standard_metadata.ingress_port == CPU_PORT) {
			standard_metadata.egress_spec = (bit<9>)hdr.packet_out.egress_port;
			standard_metadata.mcast_grp = hdr.packet_out.mcast_grp;
		}
		else {
			arp_table.apply();
		}
    }
}

#endif
