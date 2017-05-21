#ifndef NEAT_WEBRTC_TOOLS_H
#define NEAT_WEBRTC_TOOLS_H

#include <rawrtc.h>

/*
 * Client structure. Can be extended. Has to be put elsewhere later.
 */
struct client {
    char* name;
    char** ice_candidate_types;
    size_t n_ice_candidate_types;
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
        struct client* const client,
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
) ;
#endif
