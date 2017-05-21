#include <stdio.h>
#include <string.h>

#include "neat_webrtc_tools.h"


/*
 * Print the ICE transport's state.
 */
void default_ice_transport_state_change_handler(
        enum rawrtc_ice_transport_state const state,
        void* const arg // will be casted to `struct client*`
) {
printf("%s\n", __func__);
    struct client* const client = arg;
    char const * const state_name = rawrtc_ice_transport_state_to_name(state);
    (void) arg;
    printf("(%s) ICE transport state: %s\n", client->name, state_name);
}

/*
 * Print the newly gatherered local candidate.
 */
void default_ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    (void) candidate; (void) arg;
    printf("%s\n", __func__);
    print_ice_candidate(candidate, url, client);
}

/*
 * Print the ICE gatherer's error event.
 */
void default_ice_gatherer_error_handler(
        struct rawrtc_ice_candidate* const host_candidate, // read-only, nullable
        char const * const url, // read-only
        uint16_t const error_code, // read-only
        char const * const error_text, // read-only
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    (void) host_candidate; (void) error_code; (void) arg;
    printf("%s\n", __func__);
    printf("(%s) ICE gatherer error, URL: %s, reason: %s\n", client->name, url, error_text);
}

/*
 * Print the ICE gatherer's state.
 */
void default_ice_gatherer_state_change_handler(
        enum rawrtc_ice_gatherer_state const state, // read-only
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    printf("%s state=%d\n", __func__, state);
    char const * const state_name = rawrtc_ice_gatherer_state_to_name(state);
    (void) arg;
    printf("(%s) ICE gatherer state: %s\n", client->name, state_name);
}

/*
 * Print ICE candidate information.
 */
void print_ice_candidate(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        struct client* const client
) {
    if (candidate) {
        enum rawrtc_code const ignore[] = {RAWRTC_CODE_NO_VALUE};
        enum rawrtc_code error;
        char* foundation;
        enum rawrtc_ice_protocol protocol;
        uint32_t priority;
        char* ip;
        uint16_t port;
        enum rawrtc_ice_candidate_type type;
        enum rawrtc_ice_tcp_candidate_type tcp_type;
        char const* tcp_type_str = "N/A";
        char* related_address = NULL;
        uint16_t related_port = 0;
        bool is_enabled = false;
printf("%s\n", __func__);
        // Get candidate information
        if (rawrtc_ice_candidate_get_foundation(&foundation, candidate) != RAWRTC_CODE_SUCCESS) {
            printf("Error rawrtc_ice_candidate_get_foundation\n");
            exit (-1);
        }

        if (rawrtc_ice_candidate_get_protocol(&protocol, candidate) != RAWRTC_CODE_SUCCESS) {
            printf("Error rawrtc_ice_candidate_get_protocol\n");
            exit (-1);
        }

        if (rawrtc_ice_candidate_get_priority(&priority, candidate) != RAWRTC_CODE_SUCCESS) {
            printf("Error rawrtc_ice_candidate_get_priority\n");
            exit (-1);
        }

        if (rawrtc_ice_candidate_get_ip(&ip, candidate) != RAWRTC_CODE_SUCCESS) {
            printf("Error rawrtc_ice_candidate_get_ip\n");
            exit (-1);
        }

        if (rawrtc_ice_candidate_get_port(&port, candidate) != RAWRTC_CODE_SUCCESS) {
            printf("Error rawrtc_ice_candidate_get_port\n");
            exit (-1);
        }

        if (rawrtc_ice_candidate_get_type(&type, candidate) != RAWRTC_CODE_SUCCESS) {
            printf("Error rawrtc_ice_candidate_get_type\n");
            exit (-1);
        }

        error = rawrtc_ice_candidate_get_tcp_type(&tcp_type, candidate);
        switch (error) {
            case RAWRTC_CODE_SUCCESS:
                tcp_type_str = rawrtc_ice_tcp_candidate_type_to_str(tcp_type);
                break;
            case RAWRTC_CODE_NO_VALUE:
                break;
            default:
                printf("Error: %d\n", error);
                break;
        }
        if (rawrtc_ice_candidate_get_related_address(&related_address, candidate), ignore) {
            printf("Error rawrtc_ice_candidate_get_related_address\n");
        }
        if (rawrtc_ice_candidate_get_related_port(&related_port, candidate), ignore) {
            printf("Error rawrtc_ice_candidate_get_related_port\n");
        }
        is_enabled = ice_candidate_type_enabled(client, type);

        // Print candidate
        printf("(%s) ICE gatherer local candidate: foundation=%s, protocol=%s, priority=%"PRIu32""
                        ", ip=%s, port=%"PRIu16", type=%s, tcp-type=%s, related-address=%s,"
                        "related-port=%"PRIu16"; URL: %s; %s\n",
                client->name, foundation, rawrtc_ice_protocol_to_str(protocol), priority, ip, port,
                rawrtc_ice_candidate_type_to_str(type), tcp_type_str,
                related_address ? related_address : "N/A", related_port, url ? url : "N/A",
                is_enabled ? "enabled" : "disabled");

        // Unreference
        rawrtc_mem_deref(related_address);
        rawrtc_mem_deref(ip);
        rawrtc_mem_deref(foundation);
    } else {
        printf("(%s) ICE gatherer last local candidate\n", client->name);
    }
}

/*
 * Check if the ICE candidate type is enabled.
 */
bool ice_candidate_type_enabled(
        struct client* const client,
        enum rawrtc_ice_candidate_type const type
) {
    char const* const type_str = rawrtc_ice_candidate_type_to_str(type);
    size_t i;
printf("%s\n", __func__);
printf("type string=%s\n", type_str);
    // All enabled?
    if (client) {
        if (client->n_ice_candidate_types == 0) {
            return true;
        }
        printf("n_ice_candidate_types=%zu\n", client->n_ice_candidate_types);
        // Specifically enabled?
        for (i = 0; i < client->n_ice_candidate_types; ++i) {
            if (strcmp(client->ice_candidate_types[i], type_str) == 0) {
                return true;
            }
        }
    }

    // Nope
    return false;
}

/*
 * Add the ICE candidate to the remote ICE transport if the ICE
 * candidate type is enabled.
 */
void add_to_other_if_ice_candidate_type_enabled(
        struct client* const client,
        struct rawrtc_ice_candidate* const candidate,
        struct rawrtc_ice_transport* const transport
) {
printf("%s\n", __func__);
    if (candidate) {
        enum rawrtc_ice_candidate_type type;
printf("%s: candidate=%p transport=%p\n", __func__, (void *)candidate, (void *)transport);
        // Get ICE candidate type
        if (rawrtc_ice_candidate_get_type(&type, candidate) != RAWRTC_CODE_SUCCESS) {
            printf("Error getting ice candidate type\n");
            exit (-1);
        }

        // Add to other client as remote candidate (if type enabled)
        if (ice_candidate_type_enabled(client, type)) {
            if (rawrtc_ice_transport_add_remote_candidate(transport, candidate) != RAWRTC_CODE_SUCCESS) {
                printf("Error adding remote candidate\n");
                exit (-1);
            }
        }
    } else {
    printf("no local candidate\n");
        // Last candidate is always being added
        if (rawrtc_ice_transport_add_remote_candidate(transport, candidate) != RAWRTC_CODE_SUCCESS) {
            printf("Error adding last remote candidate\n");
            exit (-1);
        }
    }
}

/*
 * Print the ICE candidate pair change event.
 */
void default_ice_transport_candidate_pair_change_handler(
        struct rawrtc_ice_candidate* const local, // read-only
        struct rawrtc_ice_candidate* const remote, // read-only
        void* const arg // will be casted to `struct client*`
) {
printf("%s\n", __func__);
    struct client* const client = arg;
    (void) local; (void) remote;
    printf("(%s) ICE transport candidate pair change\n", client->name);
}

/*
 * Print the DTLS transport's state.
 */
void default_dtls_transport_state_change_handler(
        enum rawrtc_dtls_transport_state const state, // read-only
        void* const arg // will be casted to `struct client*`
) {
printf("%s\n", __func__);
    struct client* const client = arg;
    char const * const state_name = rawrtc_dtls_transport_state_to_name(state);
    printf("(%s) DTLS transport state change: %s\n", client->name, state_name);
}

/*
 * Print the DTLS transport's error event.
 */
void default_dtls_transport_error_handler(
        /* TODO: error.message (probably from OpenSSL) */
        void* const arg // will be casted to `struct client*`
) {
printf("%s\n", __func__);
    struct client* const client = arg;
    // TODO: Print error message
    printf("(%s) DTLS transport error: %s\n", client->name, "???");
}

/*
 * Print the SCTP transport's state.
 */
void default_sctp_transport_state_change_handler(
        enum rawrtc_sctp_transport_state const state,
        void* const arg // will be casted to `struct client*`
) {
printf("%s\n", __func__);
    struct client* const client = arg;
    char const * const state_name = rawrtc_sctp_transport_state_to_name(state);
    printf("(%s) SCTP transport state change: %s\n", client->name, state_name);
}

/*
 * Print the newly created data channel's parameter.
 */
void default_data_channel_handler(
        struct rawrtc_data_channel* const channel, // read-only, MUST be referenced when used
        void* const arg // will be casted to `struct client*`
) {
printf("%s\n", __func__);
    struct client* const client = arg;
    struct rawrtc_data_channel_parameters* parameters;
   // enum rawrtc_code const ignore[] = {RAWRTC_CODE_NO_VALUE};
    char* label = NULL;

    // Get data channel label and protocol
    if (rawrtc_data_channel_get_parameters(&parameters, channel) != RAWRTC_CODE_SUCCESS) {
        printf("Error getting data channel parameters\n");
        exit (-1);
    }
    if (rawrtc_data_channel_parameters_get_label(&label, parameters) != RAWRTC_CODE_SUCCESS) {
        printf("Error getting data channel label\n");
    }
    printf("(%s) New data channel instance: %s\n", client->name, label ? label : "N/A");
    rawrtc_mem_deref(label);
    rawrtc_mem_deref(parameters);
}

/*
 * Create a data channel helper instance.
 */
void data_channel_helper_create(
        struct data_channel_helper** const channel_helperp, // de-referenced
        struct client* const client,
        char* const label
) {
    // Allocate
    struct data_channel_helper* const channel =
            rawrtc_mem_zalloc(sizeof(*channel), data_channel_helper_destroy);
    if (!channel) {
        printf("no memory!");
        return;
    }

    // Set fields
    channel->client = client;
    if (rawrtc_strdup(&channel->label, label)  != RAWRTC_CODE_SUCCESS) {
        printf("Error copying label\n");
        exit (-1);
    }

    // Set pointer & done
    *channel_helperp = channel;
}

static void data_channel_helper_destroy(
        void* arg
) {
    struct data_channel_helper* const channel = arg;

    // Unset handler argument & handlers of the channel
    if (rawrtc_data_channel_unset_handlers(channel->channel)!= RAWRTC_CODE_SUCCESS) {
        printf("Error unsetting data channel handlers\n");
        exit (-1);
    }

    // Remove from list
    rawrtc_list_unlink(&channel->le);

    // Un-reference
    rawrtc_mem_deref(channel->arg);
    rawrtc_mem_deref(channel->label);
    rawrtc_mem_deref(channel->channel);
}

/*
 * Print the data channel buffered amount low event.
 */
void default_data_channel_buffered_amount_low_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct client* const client = channel->client;
    printf("(%s) Data channel buffered amount low: %s\n", client->name, channel->label);
}

/*
 * Print the data channel error event.
 */
void default_data_channel_error_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct client* const client = channel->client;
    printf("(%s) Data channel error: %s\n", client->name, channel->label);
}

/*
 * Print the data channel close event.
 */
void default_data_channel_close_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct client* const client = channel->client;
    printf("(%s) Data channel closed: %s\n", client->name, channel->label);
}

/*
 * Print the data channel's received message's size.
 */
void default_data_channel_message_handler(
        struct mbuf* const buffer,
        enum rawrtc_data_channel_message_flag const flags,
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct client* const client = channel->client;
    (void) flags;
    printf("(%s) Incoming message for data channel %s: %zu bytes\n",
                 client->name, channel->label, rawrtc_mbuf_get_left(buffer));
}

/*
 * Print the data channel open event.
 */
void default_data_channel_open_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct client* const client = channel->client;
    printf("(%s) Data channel open: %s\n", client->name, channel->label);
}
