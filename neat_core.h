#ifndef NEAT_MULTI_PREFIX_H
#define NEAT_MULTI_PREFIX_H

#include "neat_queue.h"

#define RETVAL_SUCCESS  0
#define RETVAL_FAILURE  1
#define RETVAL_IGNORE   2

#if !defined(HAVE_NETINET_SCTP_H) && !defined(SCTP_CAUSE_INVALID_STREAM)

// Error cause code constants from sctp.h / FreeBSD
// The actual codepoints are defined by RFC4960 sect. 3.3.10
/*
 * SCTP operational error codes (user visible)
 */
#define SCTP_CAUSE_NO_ERROR		0x0000
#define SCTP_CAUSE_INVALID_STREAM	0x0001
#define SCTP_CAUSE_MISSING_PARAM	0x0002
#define SCTP_CAUSE_STALE_COOKIE		0x0003
#define SCTP_CAUSE_OUT_OF_RESC		0x0004
#define SCTP_CAUSE_UNRESOLVABLE_ADDR	0x0005
#define SCTP_CAUSE_UNRECOG_CHUNK	0x0006
#define SCTP_CAUSE_INVALID_PARAM	0x0007
#define SCTP_CAUSE_UNRECOG_PARAM	0x0008
#define SCTP_CAUSE_NO_USER_DATA		0x0009
#define SCTP_CAUSE_COOKIE_IN_SHUTDOWN	0x000a
#define SCTP_CAUSE_RESTART_W_NEWADDR	0x000b
#define SCTP_CAUSE_USER_INITIATED_ABT	0x000c
#define SCTP_CAUSE_PROTOCOL_VIOLATION	0x000d

#endif // !defined(HAVE_NETINET_SCTP_H) && !defined(USRSCTP_SUPPORT)

struct neat_ctx;

//Pass data to all subscribers of event type
void neat_run_event_cb(struct neat_ctx *nc, uint8_t event_type,
        void *data);
#endif
