#ifndef __DHCP__
#define __DHCP__

control dhcp (
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
	action send_to_cpu() {
		standard_metadata.egress_spec = CPU_PORT;
		hdr.packet_in.setValid();
		hdr.packet_in.ingress_port = (bit<16>)standard_metadata.ingress_port;
	}

	action flooding() {
		standard_metadata.mcast_grp = (bit<16>)(MCAST_BASE + standard_metadata.ingress_port);
	}

	action _drop() {
		mark_to_drop(standard_metadata);
	}

    table dhcp_table {
        key = {
			standard_metadata.ingress_port: exact;
			hdr.udp.srcPort: exact;
			hdr.udp.dstPort: exact;
        }
        actions = {
			send_to_cpu;
			flooding;
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
			dhcp_table.apply();
		}
    }
}

#endif
