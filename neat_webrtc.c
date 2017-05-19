#include <stdio.h>

#include "neat.h"
#include "neat_internal.h"
#include <rawrtc.h>

#define ARRAY_SIZE(a) ((sizeof(a))/(sizeof((a)[0])))

struct rawrtc_ice_gatherer* gatherer;

void default_ice_gatherer_state_change_handler(
        enum rawrtc_ice_gatherer_state const state, // read-only
        void* const arg // will be casted to `struct client*`
);

static neat_flow *n_flow = NULL;

/*
 * Client structure. Can be extended. Has to be put elsewhere later.
 */
struct client {
    char* name;
    char** ice_candidate_types;
    size_t n_ice_candidate_types;
};

/*
 * Print the ICE gatherer's state. Stop once complete.
 */
void gatherer_state_change_handler(
        enum rawrtc_ice_gatherer_state const state, // read-only
        void* const arg // will be casted to `struct client*`
) {
printf( "%s\n", __func__);
    default_ice_gatherer_state_change_handler(state, arg);

    if (state == RAWRTC_ICE_GATHERER_COMPLETE) {
        printf("close gatherer\n");
        if (rawrtc_ice_gatherer_close(gatherer) != RAWRTC_CODE_SUCCESS) {
            printf("Error closing gatherer\n");
            exit (-1);
        }/* else {
            printf("Gatherer closed successfully\n");
            rawrtc_mem_deref (gatherer);
            printf("close rawrtc\n");
            rawrtc_close();
            printf("rawrtc_closed\n");
            neat_close(n_flow->ctx, n_flow);
        }*/
    }
    if (state == RAWRTC_ICE_GATHERER_CLOSED) {
        printf("Gatherer closed successfully\n");
        rawrtc_mem_deref(gatherer->options);
        rawrtc_mem_deref (gatherer);
        printf("close rawrtc\n");
        rawrtc_close();
        printf("rawrtc_closed\n");
        neat_close(n_flow->ctx, n_flow);
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
printf("foundation=%s\n", foundation);
        if (rawrtc_ice_candidate_get_protocol(&protocol, candidate) != RAWRTC_CODE_SUCCESS) {
            printf("Error rawrtc_ice_candidate_get_protocol\n");
            exit (-1);
        }
printf("protocol=%d\n", protocol);
        if (rawrtc_ice_candidate_get_priority(&priority, candidate) != RAWRTC_CODE_SUCCESS) {
            printf("Error rawrtc_ice_candidate_get_priority\n");
            exit (-1);
        }
printf("priority=%d\n", priority);
        if (rawrtc_ice_candidate_get_ip(&ip, candidate) != RAWRTC_CODE_SUCCESS) {
            printf("Error rawrtc_ice_candidate_get_ip\n");
            exit (-1);
        }
printf("ip=%s\n", ip);
        if (rawrtc_ice_candidate_get_port(&port, candidate) != RAWRTC_CODE_SUCCESS) {
            printf("Error rawrtc_ice_candidate_get_port\n");
            exit (-1);
        }
printf("port=%d\n", port);
        if (rawrtc_ice_candidate_get_type(&type, candidate) != RAWRTC_CODE_SUCCESS) {
            printf("Error rawrtc_ice_candidate_get_type\n");
            exit (-1);
        }
printf("type=%d\n", type);
        error = rawrtc_ice_candidate_get_tcp_type(&tcp_type, candidate);
        switch (error) {
            case RAWRTC_CODE_SUCCESS:
                tcp_type_str = rawrtc_ice_tcp_candidate_type_to_str(tcp_type);
                printf("tcp type=%s\n", tcp_type_str);
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

// TODO: return the candidate
void
neat_webrtc_gather_candidates(neat_ctx *ctx, neat_flow *flow) {
    struct rawrtc_ice_gather_options* gather_options;
   // struct rawrtc_ice_gatherer* gatherer;
    char* const stun_google_com_urls[] = {"stun:stun.l.google.com:19302",
                                          "stun:stun1.l.google.com:19302"};
 //   struct client client = {"", NULL, 0, ctx, flow};
    struct client *client = calloc(1, sizeof(struct client));;
    client->name = "A";
    client->ice_candidate_types = NULL;
    client->n_ice_candidate_types = 0;

    n_flow = flow;
    n_flow->ctx = flow->ctx;

    neat_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (rawrtc_init() != RAWRTC_CODE_SUCCESS) {
        neat_log(ctx, NEAT_LOG_ERROR, "Error initializing RawRTC");
        exit (-1);
    }
printf("n_ice_candidate_types=%zu\n", client->n_ice_candidate_types);
    rawrtc_dbg_init(DBG_DEBUG, DBG_ALL);

    printf("ctx=%p loop=%p\n", (void *)ctx, (void *)ctx->loop);
    rawrtc_set_uv_loop((void *)(ctx->loop));

    rawrtc_alloc_fds(128);

    if (rawrtc_ice_gather_options_create(&gather_options, RAWRTC_ICE_GATHER_POLICY_ALL) != RAWRTC_CODE_SUCCESS) {
        neat_log(ctx, NEAT_LOG_ERROR, "Error creating ice_gather_options");
        exit (-1);
    }
printf("rawrtc_ice_gather_options_create successfully\n");

    if (rawrtc_ice_gather_options_add_server(
            gather_options, stun_google_com_urls, ARRAY_SIZE(stun_google_com_urls),
            NULL, NULL, RAWRTC_ICE_CREDENTIAL_TYPE_NONE) != RAWRTC_CODE_SUCCESS) {
        neat_log(ctx, NEAT_LOG_ERROR, "Error adding server");
        exit (-1);
    }
printf("rawrtc_ice_gather_options_add_server successfully\n");

    // Setup client
  //  client.name = "A";

    // Create ICE gatherer
    if (rawrtc_ice_gatherer_create(
            &gatherer, gather_options,
            gatherer_state_change_handler, default_ice_gatherer_error_handler,
            default_ice_gatherer_local_candidate_handler, client) != RAWRTC_CODE_SUCCESS) {
        neat_log(ctx, NEAT_LOG_ERROR, "Error creating ice gatherer");
        exit (-1);
    } else {
        neat_log(ctx, NEAT_LOG_DEBUG, "Ice gatherer created successfully");
        printf("n_ice_candidate_types=%zu\n", client->n_ice_candidate_types);
    }

    if (rawrtc_ice_gatherer_gather(gatherer, NULL) != RAWRTC_CODE_SUCCESS) {
        neat_log(ctx, NEAT_LOG_ERROR, "Error gathering candidates");
        exit (-1);
    } else {
        neat_log(ctx, NEAT_LOG_DEBUG, "Ice candidates gathered successfully");
    }
}
