#ifndef NEAT_MULTI_PREFIX_H
#define NEAT_MULTI_PREFIX_H

#include "neat_queue.h"

#define RETVAL_SUCCESS  0
#define RETVAL_FAILURE  1
#define RETVAL_IGNORE   2

// Error cause code constants from sctp.h / FreeBSD
// The actual codepoints are defined by RFC4960 sect. 3.3.10
/*
 * SCTP operational error codes (user visible)
 */
enum neat_sctp_cause_code {
    NEAT_SCTP_CAUSE_NO_ERROR = 			0x0000,
    NEAT_SCTP_CAUSE_INVALID_STREAM =		0x0001,
    NEAT_SCTP_CAUSE_MISSING_PARAM =		0x0002,
    NEAT_SCTP_CAUSE_STALE_COOKIE =		0x0003,
    NEAT_SCTP_CAUSE_OUT_OF_RESC	=		0x0004,
    NEAT_SCTP_CAUSE_UNRESOLVABLE_ADDR =		0x0005,
    NEAT_SCTP_CAUSE_UNRECOG_CHUNK =		0x0006,
    NEAT_SCTP_CAUSE_INVALID_PARAM =		0x0007,
    NEAT_SCTP_CAUSE_UNRECOG_PARAM =		0x0008,
    NEAT_SCTP_CAUSE_NO_USER_DATA =		0x0009,
    NEAT_SCTP_CAUSE_COOKIE_IN_SHUTDOWN =	0x000a,
    NEAT_SCTP_CAUSE_RESTART_W_NEWADDR = 	0x000b,
    NEAT_SCTP_CAUSE_USER_INITIATED_ABT = 	0x000c,
    NEAT_SCTP_CAUSE_PROTOCOL_VIOLATION = 	0x000d
};

struct neat_ctx;

//Pass data to all subscribers of event type
void neat_run_event_cb(struct neat_ctx *nc, uint8_t event_type,
        void *data);
#endif
