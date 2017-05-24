#ifndef NEAT_WEBRTC_TOOLS_H
#define NEAT_WEBRTC_TOOLS_H

#include <rawrtc.h>

#define PARAMETERS_MAX_LENGTH  8192

/*
 * Socket event flags
 */
#define SCTP_EVENT_READ		0x0001	/* socket is readable */
#define SCTP_EVENT_WRITE	0x0002	/* socket is writeable */
#define SCTP_EVENT_ERROR	0x0004	/* socket has an error state */

/*
 * Client structure. Can be extended. Has to be put elsewhere later.
 */
struct client {
    char* name;
    char** ice_candidate_types;
    size_t n_ice_candidate_types;
};

/*
 * SCTP parameters that need to be negotiated.
 */
struct sctp_parameters {
    struct rawrtc_sctp_capabilities* capabilities;
    uint16_t port;
};

struct parameters {
    struct rawrtc_ice_parameters* ice_parameters;
    struct rawrtc_ice_candidates* ice_candidates;
    struct rawrtc_dtls_parameters* dtls_parameters;
    struct sctp_parameters sctp_parameters;
};

struct peer_connection {
    char* name;
    char** ice_candidate_types;
    size_t n_ice_candidate_types;
    struct rawrtc_ice_gather_options* gather_options;
    enum rawrtc_ice_role role;
    struct rawrtc_certificate* certificate;
    struct rawrtc_ice_gatherer* gatherer;
    struct rawrtc_ice_transport* ice_transport;
    struct rawrtc_dtls_transport* dtls_transport;
    struct rawrtc_sctp_transport* sctp_transport;
    struct rawrtc_data_transport* data_transport;
    struct rawrtc_list data_channels;
    struct parameters local_parameters;
    struct parameters remote_parameters;
    struct neat_flow *flow;
    struct neat_ctx *ctx;
};



void default_ice_gatherer_state_change_handler(
        enum rawrtc_ice_gatherer_state const state, // read-only
        void* const arg // will be casted to `struct client*`
);

void default_ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg // will be casted to `struct client*`
);

void default_ice_transport_state_change_handler(
        enum rawrtc_ice_transport_state const state,
        void* const arg // will be casted to `struct client*`
);

void default_ice_gatherer_error_handler(
        struct rawrtc_ice_candidate* const host_candidate, // read-only, nullable
        char const * const url, // read-only
        uint16_t const error_code, // read-only
        char const * const error_text, // read-only
        void* const arg // will be casted to `struct client*`
);

void print_ice_candidate(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        struct client* const client
);

bool ice_candidate_type_enabled(
        struct client* const client,
        enum rawrtc_ice_candidate_type const type
);

void add_to_other_if_ice_candidate_type_enabled(
        struct client* const client,
        struct rawrtc_ice_candidate* const candidate,
        struct rawrtc_ice_transport* const transport
);

void default_ice_transport_candidate_pair_change_handler(
        struct rawrtc_ice_candidate* const local, // read-only
        struct rawrtc_ice_candidate* const remote, // read-only
        void* const arg // will be casted to `struct client*`
);

void default_dtls_transport_state_change_handler(
        enum rawrtc_dtls_transport_state const state, // read-only
        void* const arg // will be casted to `struct client*`
);

void default_dtls_transport_error_handler(
        void* const arg // will be casted to `struct client*`
);

void default_sctp_transport_state_change_handler(
        enum rawrtc_sctp_transport_state const state,
        void* const arg // will be casted to `struct client*`
);

void default_data_channel_handler(
        struct rawrtc_data_channel* const channel, // read-only, MUST be referenced when used
        void* const arg // will be casted to `struct client*`
);

void data_channel_helper_create(
        struct data_channel_helper** const channel_helperp, // de-referenced
        struct peer_connection* const client,
        char* const label
);

void default_data_channel_buffered_amount_low_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
);

void default_data_channel_error_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
);

void default_data_channel_close_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
);

void default_data_channel_message_handler(
        struct mbuf* const buffer,
        enum rawrtc_data_channel_message_flag const flags,
        void* const arg // will be casted to `struct data_channel_helper*`
);

void default_data_channel_open_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
);

static void data_channel_helper_destroy(
        void* arg
);

enum rawrtc_code get_json_stdin(
        struct odict** const dictp // de-referenced
);

enum rawrtc_code dict_get_entry(
        void* const valuep,
        struct odict* const parent,
        char* const key,
        enum odict_type const type,
        bool required
);

enum rawrtc_code get_ice_parameters(
        struct rawrtc_ice_parameters** const parametersp,
        struct odict* const dict
);

enum rawrtc_code get_ice_candidates(
        struct rawrtc_ice_candidates** const candidatesp,
        struct odict* const dict,
        struct client* const client
);

enum rawrtc_code get_dtls_parameters(
        struct rawrtc_dtls_parameters** const parametersp,
        struct odict* const dict
);

enum rawrtc_code get_sctp_parameters(
        struct sctp_parameters* const parameters,
        struct odict* const dict
);

void set_ice_candidates(
        struct rawrtc_ice_candidates* const parameters,
        struct odict* const array
);

void set_ice_parameters(
        struct rawrtc_ice_parameters* const parameters,
        struct odict* const dict
);

void set_sctp_parameters(
        struct rawrtc_sctp_transport* const transport,
        struct sctp_parameters* const parameters,
        struct odict* const dict
);

void set_dtls_parameters(
        struct rawrtc_dtls_parameters* const parameters,
        struct odict* const dict
);

enum rawrtc_code get_ice_role(
        enum rawrtc_ice_role* const rolep, // de-referenced
        uint8_t role
);

static void ice_candidates_destroy(
        void* arg
);

enum rawrtc_code dict_get_uint32(
        uint32_t* const valuep,
        struct odict* const parent,
        char* const key,
        bool required
);

enum rawrtc_code dict_get_uint16(
        uint16_t* const valuep,
        struct odict* const parent,
        char* const key,
        bool required
);

void data_channel_helper_create_from_channel(
        struct data_channel_helper** const channel_helperp, // de-referenced
        struct rawrtc_data_channel* channel,
        struct client* const client,
        void* const arg // nullable
);

void rawrtc_stop_client(struct peer_connection *pc);
#endif
