#ifndef NEAT_PROPERTY_HELPERS_H
#define NEAT_PROPERTY_HELPERS_H

#include <stdint.h>

#define NEAT_KEYVAL(key,value) ("{ \"" #key "\": " #value" }")

#define NEAT_PROPERTY_TRANSPORT ("transport")

struct neat_transport_property {
    char *name;
    char *property_name;
    uint32_t protocol_no;
};

#define NEAT_TRANSPORT_PROPERTY(name, propname, protonum)		\
    {									\
        "##name",							\
	propname,							\
	protonum							\
    }

#define NEAT_PROPERTY_TRANSPORT_TCP ("transport_TCP")
#define NEAT_PROPERTY_TRANSPORT_SCTP ("transport_SCTP")
#define NEAT_PROPERTY_TRANSPORT_UDP ("transport_UDP")
#define NEAT_PROPERTY_TRANSPORT_UDPLITE ("transport_UDPlite")

// NEAT_MAX_NUM_PROTO defined in neat_internal.h

uint8_t neat_property_translate_protocols_old(uint64_t propertyMask,
        int protocols[]);
uint8_t neat_property_translate_protocols(json_t *candidates,
					  int protocols[]);

#endif
