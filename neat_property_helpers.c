#include <jansson.h>
#include "neat_property_helpers.h"
#include "neat.h"
#include "neat_log.h"
#include "neat_internal.h"

static struct neat_transport_property transports[] = {
    NEAT_TRANSPORT_PROPERTY(TCP, "transport_TCP", IPPROTO_TCP),
#ifdef IPPROTO_SCTP
    NEAT_TRANSPORT_PROPERTY(SCTP, "transport_SCTP", IPPROTO_SCTP),
#endif
    NEAT_TRANSPORT_PROPERTY(UDP, "transport_UDP", IPPROTO_UDP),
#ifdef IPPROTO_UDPLITE
    NEAT_TRANSPORT_PROPERTY(UDPlite, "transport_UDPlite", IPPROTO_UDPLITE)
#endif
};

uint8_t neat_property_translate_protocols_old(uint64_t propertyMask,
        int protocols[])
{
    uint8_t nr_of_protocols;

    nr_of_protocols = 0;

    /* Check for stupid settings */
    if ((propertyMask & NEAT_PROPERTY_SCTP_BANNED) &&
        (propertyMask & NEAT_PROPERTY_TCP_BANNED) &&
        (propertyMask & NEAT_PROPERTY_UDP_BANNED) &&
        (propertyMask & NEAT_PROPERTY_UDPLITE_BANNED))
        return nr_of_protocols;
    if ((propertyMask & NEAT_PROPERTY_CONGESTION_CONTROL_REQUIRED) &&
        (propertyMask & NEAT_PROPERTY_CONGESTION_CONTROL_BANNED))
        return nr_of_protocols;
    if ((propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_REQUIRED) &&
        (propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_BANNED))
        return nr_of_protocols;
    if ((propertyMask & NEAT_PROPERTY_SCTP_REQUIRED) &&
        (propertyMask & NEAT_PROPERTY_SCTP_BANNED))
        return nr_of_protocols;
    if ((propertyMask & NEAT_PROPERTY_TCP_REQUIRED) &&
        (propertyMask & NEAT_PROPERTY_TCP_BANNED))
        return nr_of_protocols;
    if ((propertyMask & NEAT_PROPERTY_UDP_REQUIRED) &&
        (propertyMask & NEAT_PROPERTY_UDP_BANNED))
        return nr_of_protocols;
    if ((propertyMask & NEAT_PROPERTY_UDPLITE_REQUIRED) &&
        (propertyMask & NEAT_PROPERTY_UDPLITE_BANNED))
        return nr_of_protocols;

    /* Check explicit protocol requests first */
    if (propertyMask & NEAT_PROPERTY_SCTP_REQUIRED) {
#ifdef IPPROTO_SCTP
        if (((propertyMask & NEAT_PROPERTY_TCP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_UDP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_UDPLITE_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_CONGESTION_CONTROL_BANNED) == 0))
            protocols[nr_of_protocols++] = IPPROTO_SCTP;
#endif
        return nr_of_protocols;
    }
    if (propertyMask & NEAT_PROPERTY_TCP_REQUIRED) {
        if (((propertyMask & NEAT_PROPERTY_SCTP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_UDP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_UDPLITE_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_MESSAGE) == 0) &&
            ((propertyMask & NEAT_PROPERTY_CONGESTION_CONTROL_BANNED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_BANNED) == 0))
            protocols[nr_of_protocols++] = IPPROTO_TCP;
        return nr_of_protocols;
    }
    if (propertyMask & NEAT_PROPERTY_UDP_REQUIRED) {
        if (((propertyMask & NEAT_PROPERTY_SCTP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_TCP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_UDPLITE_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_CONGESTION_CONTROL_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_REQUIRED) == 0))
            protocols[nr_of_protocols++] = IPPROTO_UDP;
        return nr_of_protocols;
    }
    if (propertyMask & NEAT_PROPERTY_UDPLITE_REQUIRED) {
#ifdef IPPROTO_UDPLITE
        if (((propertyMask & NEAT_PROPERTY_SCTP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_TCP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_UDP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_CONGESTION_CONTROL_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_REQUIRED) == 0))
            protocols[nr_of_protocols++] = IPPROTO_UDPLITE;
#endif
        return nr_of_protocols;
    }

    /* Finally the more complex part */
    if (propertyMask & NEAT_PROPERTY_CONGESTION_CONTROL_REQUIRED) {
#ifdef IPPROTO_SCTP
        if ((propertyMask & NEAT_PROPERTY_SCTP_BANNED) == 0)
            protocols[nr_of_protocols++] = IPPROTO_SCTP;
#endif
        if (((propertyMask & NEAT_PROPERTY_MESSAGE) == 0) &&
            ((propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_BANNED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_TCP_BANNED) == 0))
            protocols[nr_of_protocols++] = IPPROTO_TCP;
    } else if (propertyMask & NEAT_PROPERTY_CONGESTION_CONTROL_BANNED) {
        if ((propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_REQUIRED) == 0) {
            if ((propertyMask & NEAT_PROPERTY_UDP_BANNED) == 0)
                protocols[nr_of_protocols++] = IPPROTO_UDP;
#ifdef IPPROTO_UDPLITE
            if ((propertyMask & NEAT_PROPERTY_UDPLITE_BANNED) == 0)
                protocols[nr_of_protocols++] = IPPROTO_UDPLITE;
#endif
        }
    } else {
#ifdef IPPROTO_SCTP
        if ((propertyMask & NEAT_PROPERTY_SCTP_BANNED) == 0)
            protocols[nr_of_protocols++] = IPPROTO_SCTP;
#endif
        if (((propertyMask & NEAT_PROPERTY_MESSAGE) == 0) &&
            ((propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_BANNED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_TCP_BANNED) == 0))
            protocols[nr_of_protocols++] = IPPROTO_TCP;
        if ((propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_REQUIRED) == 0) {
            if ((propertyMask & NEAT_PROPERTY_UDP_BANNED) == 0)
                protocols[nr_of_protocols++] = IPPROTO_UDP;
#ifdef IPPROTO_UDPLITE
            if ((propertyMask & NEAT_PROPERTY_UDPLITE_BANNED) == 0)
                protocols[nr_of_protocols++] = IPPROTO_UDPLITE;
#endif
        }
    }

    return nr_of_protocols;
}

// Extract which protocols to run HE on from candidate set.
uint8_t neat_property_translate_protocols(json_t *candidates,
        int protocols[])
{
    uint8_t nr_of_protocols;
    size_t idx;
    json_t *candidate, *transport, *val;
    int i, j, found;
    int protocol_count = (int)sizeof(transports) / (int)sizeof(struct neat_transport_property);

    nr_of_protocols = 0;

    json_array_foreach(candidates, idx, candidate) {
	neat_log(NEAT_LOG_DEBUG, "Checking protocols set for candidate %d...", idx);
	if (!json_is_object(candidate)) {
	    neat_log(NEAT_LOG_ERROR, "Candidate %d is not a JSON object.\n",
		     idx);
	    return nr_of_protocols;
	}

	for (i = 0; i < protocol_count; i++) {
	    transport = json_object_get(candidate, transports[i].property_name);
	    neat_log(NEAT_LOG_DEBUG, "Checking candidate for %s", transports[i].name);
	    if (transport != NULL) {
		if (!json_is_object(transport)) {
		    neat_log(NEAT_LOG_ERROR, "Candidate %d: transport type " \
			     "'%s' not specified as JSON object.\n", idx, transports[i].name);
		    return nr_of_protocols;
		}

		val = json_object_get(transport, "value");
		if (val == NULL || (!json_is_true(val) && !json_is_false(val))) {
		    neat_log(NEAT_LOG_ERROR, "Candidate %d: transport type " \
			     "'%s' has invalid 'value' field.\n", idx, transports[i].name);
		    return nr_of_protocols;
		}

		if (json_is_true(val)) {
		    found = 0;
		    for (j = 0; j < nr_of_protocols; j++) {
			if (protocols[j] == transports[i].protocol_no) {
			    found = 1;
			    break;
			}
		    }

		    if (!found)
			protocols[nr_of_protocols++] = transports[i].protocol_no;
		    neat_log(NEAT_LOG_DEBUG, "Candidate enabled %s", transports[i].name);
		}
	    }
	}
    }

    return nr_of_protocols;
}
