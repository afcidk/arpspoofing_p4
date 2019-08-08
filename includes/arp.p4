#ifndef __ARP__
#define __ARP__

control arp (
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
	register<bit<32>>(4) ipmac_ip;
	register<bit<48>>(8) ipmac_mac;
	register<bit<2>>(1)  cache_idx;
	
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
			bit<2> idx;
			bit<32> m1; ipmac_ip.read(m1, 0);
			bit<32> m2; ipmac_ip.read(m2, 1);
			bit<32> m3; ipmac_ip.read(m3, 2);
			bit<32> m4; ipmac_ip.read(m4, 3);
			if (hdr.arp.srcIPAddr == m1)      ipmac_mac.write(0, hdr.arp.srcMacAddr);
			else if (hdr.arp.srcIPAddr == m2) ipmac_mac.write(1, hdr.arp.srcMacAddr);
			else if (hdr.arp.srcIPAddr == m3) ipmac_mac.write(2, hdr.arp.srcMacAddr);
			else if (hdr.arp.srcIPAddr == m4) ipmac_mac.write(3, hdr.arp.srcMacAddr);
			else {
				cache_idx.read(idx, 0);
				ipmac_ip.write((bit<32>)idx, hdr.arp.srcIPAddr);
				ipmac_mac.write((bit<32>)idx, hdr.arp.srcMacAddr);
				idx = idx+1; // Will overflow automatically, no need to handle
				cache_idx.write(0, idx);
			}
		}
		else {
			// Find in cache first
			bit<32> m1; ipmac_ip.read(m1, 0);
			bit<32> m2; ipmac_ip.read(m2, 1);
			bit<32> m3; ipmac_ip.read(m3, 2);
			bit<32> m4; ipmac_ip.read(m4, 3);
			bit<3> idx = 7;
			if (hdr.arp.dstIPAddr == m1)      idx = 0;
			else if (hdr.arp.dstIPAddr == m2) idx = 1;
			else if (hdr.arp.dstIPAddr == m3) idx = 2;
			else if (hdr.arp.dstIPAddr == m4) idx = 3;

			if (idx == 7) { // slowpath
				arp_table.apply();
			}
			else { // fastpath
				standard_metadata.egress_spec = standard_metadata.ingress_port;
				bit<48> result; ipmac_mac.read(result, (bit<32>)idx);
				bit<32> tmp = hdr.arp.dstIPAddr;
				hdr.arp.oper = 2;
				hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
				hdr.ethernet.srcAddr = result;
				hdr.arp.dstIPAddr = hdr.arp.srcIPAddr;
				hdr.arp.dstMacAddr = hdr.arp.srcMacAddr;
				hdr.arp.srcIPAddr = tmp;
				hdr.arp.srcMacAddr = result;
			}
		}
    }
}

#endif
