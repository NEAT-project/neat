#include "neat_property_helpers.h"
#include "neat.h"

uint8_t neat_property_translate_protocols(uint64_t propertyMask,
        neat_protocol_stack_type stacks[])
{
    uint8_t nr_of_stacks;

    nr_of_stacks = 0;

    /* Check for stupid settings */
    if ((propertyMask & NEAT_PROPERTY_SCTP_BANNED) &&
        (propertyMask & NEAT_PROPERTY_TCP_BANNED) &&
        (propertyMask & NEAT_PROPERTY_UDP_BANNED) &&
        (propertyMask & NEAT_PROPERTY_UDPLITE_BANNED))
        return nr_of_stacks;
    if ((propertyMask & NEAT_PROPERTY_CONGESTION_CONTROL_REQUIRED) &&
        (propertyMask & NEAT_PROPERTY_CONGESTION_CONTROL_BANNED))
        return nr_of_stacks;
    if ((propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_REQUIRED) &&
        (propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_BANNED))
        return nr_of_stacks;
    if ((propertyMask & NEAT_PROPERTY_SCTP_REQUIRED) &&
        (propertyMask & NEAT_PROPERTY_SCTP_BANNED))
        return nr_of_stacks;
    if ((propertyMask & NEAT_PROPERTY_TCP_REQUIRED) &&
        (propertyMask & NEAT_PROPERTY_TCP_BANNED))
        return nr_of_stacks;
    if ((propertyMask & NEAT_PROPERTY_UDP_REQUIRED) &&
        (propertyMask & NEAT_PROPERTY_UDP_BANNED))
        return nr_of_stacks;
    if ((propertyMask & NEAT_PROPERTY_UDPLITE_REQUIRED) &&
        (propertyMask & NEAT_PROPERTY_UDPLITE_BANNED))
        return nr_of_stacks;

    /* Check explicit protocol requests first */
    if (propertyMask & NEAT_PROPERTY_SCTP_REQUIRED) {
        if (((propertyMask & NEAT_PROPERTY_TCP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_UDP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_UDPLITE_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_CONGESTION_CONTROL_BANNED) == 0)) {
            stacks[nr_of_stacks++] = NEAT_STACK_SCTP;
            stacks[nr_of_stacks++] = NEAT_STACK_SCTP_UDP;
        }
        return nr_of_stacks;
    }
    if (propertyMask & NEAT_PROPERTY_TCP_REQUIRED) {
        if (((propertyMask & NEAT_PROPERTY_SCTP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_UDP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_UDPLITE_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_MESSAGE) == 0) &&
            ((propertyMask & NEAT_PROPERTY_CONGESTION_CONTROL_BANNED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_BANNED) == 0))
            stacks[nr_of_stacks++] = NEAT_STACK_TCP;
        return nr_of_stacks;
    }
    if (propertyMask & NEAT_PROPERTY_UDP_REQUIRED) {
        if (((propertyMask & NEAT_PROPERTY_SCTP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_TCP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_UDPLITE_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_CONGESTION_CONTROL_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_REQUIRED) == 0))
            stacks[nr_of_stacks++] = NEAT_STACK_UDP;
        return nr_of_stacks;
    }
    if (propertyMask & NEAT_PROPERTY_UDPLITE_REQUIRED) {
        if (((propertyMask & NEAT_PROPERTY_SCTP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_TCP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_UDP_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_CONGESTION_CONTROL_REQUIRED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_REQUIRED) == 0))
            stacks[nr_of_stacks++] = NEAT_STACK_UDPLITE;
        return nr_of_stacks;
    }

    /* Finally the more complex part */
    if (propertyMask & NEAT_PROPERTY_CONGESTION_CONTROL_REQUIRED) {
        if ((propertyMask & NEAT_PROPERTY_SCTP_BANNED) == 0) {
            stacks[nr_of_stacks++] = NEAT_STACK_SCTP;
            stacks[nr_of_stacks++] = NEAT_STACK_SCTP_UDP;
        }
        if (((propertyMask & NEAT_PROPERTY_MESSAGE) == 0) &&
            ((propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_BANNED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_TCP_BANNED) == 0))
            stacks[nr_of_stacks++] = NEAT_STACK_TCP;
    } else if (propertyMask & NEAT_PROPERTY_CONGESTION_CONTROL_BANNED) {
        if ((propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_REQUIRED) == 0) {
            if ((propertyMask & NEAT_PROPERTY_UDP_BANNED) == 0)
                stacks[nr_of_stacks++] = NEAT_STACK_UDP;
            if ((propertyMask & NEAT_PROPERTY_UDPLITE_BANNED) == 0)
                stacks[nr_of_stacks++] = NEAT_STACK_UDPLITE;
        }
    } else {
        if ((propertyMask & NEAT_PROPERTY_SCTP_BANNED) == 0) {
            stacks[nr_of_stacks++] = NEAT_STACK_SCTP;
            stacks[nr_of_stacks++] = NEAT_STACK_SCTP_UDP;
        }
        if (((propertyMask & NEAT_PROPERTY_MESSAGE) == 0) &&
            ((propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_BANNED) == 0) &&
            ((propertyMask & NEAT_PROPERTY_TCP_BANNED) == 0))
            stacks[nr_of_stacks++] = NEAT_STACK_TCP;
        if ((propertyMask & NEAT_PROPERTY_RETRANSMISSIONS_REQUIRED) == 0) {
            if ((propertyMask & NEAT_PROPERTY_UDP_BANNED) == 0)
                stacks[nr_of_stacks++] = NEAT_STACK_UDP;
            if ((propertyMask & NEAT_PROPERTY_UDPLITE_BANNED) == 0)
                stacks[nr_of_stacks++] = NEAT_STACK_UDPLITE;
        }
    }

    return nr_of_stacks;
}
