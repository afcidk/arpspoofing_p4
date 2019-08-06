#ifndef __LP__
#define __LP__
#define ETHERTYPE_LP 0x5ff
#define ETHERTYPE_LRP 0x600

control lp (
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
	action send_to_cpu() {
		standard_metadata.egress_spec = CPU_PORT;
		hdr.packet_in.setValid();
		hdr.packet_in.ingress_port = (bit<16>)standard_metadata.ingress_port;
	}

	action no_action() {
	}

    table lp_table {
        key = {
			hdr.ethernet.etherType: exact;
        }
        actions = {
			send_to_cpu;
			no_action;
        }
        size = 1024;
        default_action = no_action();
    }

    apply {
		if (standard_metadata.ingress_port == CPU_PORT) {
			standard_metadata.egress_spec = (bit<9>)hdr.packet_out.egress_port;
			standard_metadata.mcast_grp = hdr.packet_out.mcast_grp;
		}
		else {
			lp_table.apply();
		}
    }
}

#endif
