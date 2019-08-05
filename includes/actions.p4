#ifndef __ACTIONS__
#define __ACTIONS__

#include "headers.p4"

action drop(inout standard_metadata_t standard_metadata) {
    mark_to_drop(standard_metadata);
}

#endif
