/*
    Basic P4 switch program for tutor. (with simple functional support)
*/
#include <core.p4>
#include <v1model.p4>

#include "includes/headers.p4"
#include "includes/actions.p4"
#include "includes/checksums.p4"
#include "includes/parser.p4"

// application
#include "includes/mac_forward.p4"
#include "includes/arp.p4"
#include "includes/dhcp.p4"
#include "includes/lp.p4"

//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------
control basic_tutorial_ingress(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    apply {
        /* Pipelines in Ingress */
		if (hdr.ethernet.etherType == ETHERTYPE_LP || \
			hdr.ethernet.etherType == ETHERTYPE_LRP) {
			lp.apply(hdr, metadata, standard_metadata);
		}
		else {
			if(hdr.dhcp.isValid())
				dhcp.apply(hdr, metadata, standard_metadata);
			if(hdr.arp.isValid())
				arp.apply(hdr, metadata, standard_metadata);

			if (hdr.ipv4.isValid() && !hdr.dhcp.isValid())
				mac.apply(hdr, metadata, standard_metadata);
		}
    }
}

//------------------------------------------------------------------------------
// EGRESS PIPELINE
//------------------------------------------------------------------------------
control basic_tutorial_egress(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    apply {
        /* Pipelines in Egress */
    }
}

//------------------------------------------------------------------------------
// SWITCH ARCHITECTURE
//------------------------------------------------------------------------------
V1Switch(
    basic_tutor_switch_parser(),
    basic_tutor_verifyCk(),
    basic_tutorial_ingress(),
    basic_tutorial_egress(),
    basic_tutor_computeCk(),
    basic_tutor_switch_deparser()
) main;
