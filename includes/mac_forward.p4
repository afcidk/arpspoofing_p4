#ifndef __MAC_FORWARD__
#define __MAC_FORWARD__

control mac (
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
	action forward(bit<9> outPort) {
		standard_metadata.egress_spec = outPort;
	}
	
	action _drop() {
		mark_to_drop(standard_metadata);
	}

    table mac_table {
        key = {
			hdr.ethernet.dstAddr: exact;
			standard_metadata.ingress_port: exact;
        }
        actions = {
			forward;
			_drop;
        }
        size = 1024;
        default_action = _drop();
    }

    apply {
		mac_table.apply();
    }
}

#endif
