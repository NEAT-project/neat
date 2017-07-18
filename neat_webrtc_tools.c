#include <stdio.h>
#include <string.h>
#if defined(WEBRTC_SUPPORT)

#include "neat_webrtc_tools.h"
#include "neat_internal.h"


/*
 * Print the ICE transport's state.
 */
void default_ice_transport_state_change_handler(
        enum rawrtc_ice_transport_state const state,
        void* const arg // will be casted to `struct client*`
) {
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
    printf("(%s) ICE gatherer error, URL: %s, reason: %s\n", client->name, url, error_text);
}

/*
 * Print the ICE gatherer's state.
 */
void default_ice_gatherer_state_change_handler(
        enum rawrtc_ice_gatherer_state const state, // read-only
        void* const arg // will be casted to `struct peer_connection*`
) {
    struct peer_connection* const client = arg;
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

    // All enabled?
    if (client) {
        if (client->n_ice_candidate_types == 0) {
            return true;
        }
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
    if (candidate) {
        enum rawrtc_ice_candidate_type type;
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
        struct peer_connection* const client,
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
    channel->client = (struct client *)client;
    channel->arg = client;
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
   // rawrtc_mem_deref(channel->arg);
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
    printf("(%s) Data channel buffered amount low: %s, arg=data_channel_helper\n", client->name, channel->label);
}

/*
 * Print the data channel error event.
 */
void default_data_channel_error_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct client* const client = channel->client;
    printf("(%s) Data channel error: %s: arg=data_channel_helper\n", client->name, channel->label);
}

/*
 * Print the data channel close event.
 */
void default_data_channel_close_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct client* const client = channel->client;
    printf("(%s) Data channel closed: %s: arg=data_channel_helper\n", client->name, channel->label);
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

/*
 * Parse buffer containing parameters it to a dictionary.
 */
enum rawrtc_code get_json_buffer(
        struct odict** const dictp, // de-referenced
        char *buffer
) {
    size_t length = strlen(buffer);

    // Exit?
    if (length == 1 && buffer[0] == '\n') {
        return RAWRTC_CODE_NO_VALUE;
    }

    // Decode JSON
    if (rawrtc_json_decode_odict(dictp, 16, buffer, length, 3) != RAWRTC_CODE_SUCCESS) {
        return RAWRTC_CODE_NO_VALUE;
    }
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get JSON from stdin and parse it to a dictionary.
 */
enum rawrtc_code get_json_stdin(
        struct odict** const dictp // de-referenced
) {
    char buffer[PARAMETERS_MAX_LENGTH];
    size_t length;

    // Get message from stdin
    if (!fgets((char*) buffer, PARAMETERS_MAX_LENGTH, stdin)) {
        printf("Error polling stdin");
    }
    length = strlen(buffer);

    // Exit?
    if (length == 1 && buffer[0] == '\n') {
        return RAWRTC_CODE_NO_VALUE;
    }

    // Decode JSON
    if (rawrtc_json_decode_odict(dictp, 16, buffer, length, 3) != RAWRTC_CODE_SUCCESS) {
    	return RAWRTC_CODE_NO_VALUE;
    }
    return RAWRTC_CODE_SUCCESS;
}

static void dtls_fingerprints_destroy(
        void* arg
) {
    struct rawrtc_dtls_fingerprints* const fingerprints = arg;
    size_t i;

    // Un-reference each item
    for (i = 0; i < fingerprints->n_fingerprints; ++i) {
        rawrtc_mem_deref(fingerprints->fingerprints[i]);
    }
}

/*
 * Get a dictionary entry and store it in `*valuep`.
 */
enum rawrtc_code dict_get_entry(
        void* const valuep,
        struct odict* const parent,
        char* const key,
        enum odict_type const type,
        bool required
) {
    struct odict_entry const * entry;

    // Check arguments
    if (!valuep || !parent || !key) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Do lookup
    entry = rawrtc_odict_lookup(parent, key);

    // Check for entry
    if (!entry) {
        if (required) {
            printf("'%s' missing\n", key);
            return RAWRTC_CODE_INVALID_ARGUMENT;
        } else {
            return RAWRTC_CODE_NO_VALUE;
        }
    }

    // Check for type
    if (entry->type != type) {
        printf("'%s' is of different type than expected\n", key);
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set value according to type
    switch (type) {
        case ODICT_OBJECT:
        case ODICT_ARRAY:
            *((struct odict** const) valuep) = entry->u.odict;
            break;
        case ODICT_STRING:
            *((char** const) valuep) = entry->u.str;
            break;
        case ODICT_INT:
            *((int64_t* const) valuep) = entry->u.integer;
            break;
        case ODICT_DOUBLE:
            *((double* const) valuep) = entry->u.dbl;
            break;
        case ODICT_BOOL:
            *((bool* const) valuep) = entry->u.boolean;
            break;
        case ODICT_NULL:
            *((char** const) valuep) = NULL; // meh!
            break;
        default:
            return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get ICE parameters from dictionary.
 */
enum rawrtc_code get_ice_parameters(
        struct rawrtc_ice_parameters** const parametersp,
        struct odict* const dict
) {
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;
    char* username_fragment;
    char* password;
    bool ice_lite;

    // Get ICE parameters
    error |= dict_get_entry(&username_fragment, dict, "usernameFragment", ODICT_STRING, true);
    error |= dict_get_entry(&password, dict, "password", ODICT_STRING, true);
    error |= dict_get_entry(&ice_lite, dict, "iceLite", ODICT_BOOL, true);
    if (error) {
        return error;
    }

    // Create ICE parameters instance
    return rawrtc_ice_parameters_create(parametersp, username_fragment, password, ice_lite);
}

static void ice_candidates_destroy(
        void* arg
) {
    struct rawrtc_ice_candidates* const candidates = arg;
    size_t i;

    // Un-reference each item
    for (i = 0; i < candidates->n_candidates; ++i) {
        rawrtc_mem_deref(candidates->candidates[i]);
    }
}

/*
 * Get ICE candidates from dictionary.
 * Filter by enabled ICE candidate types if `client` argument is set to
 * non-NULL.
 */
enum rawrtc_code get_ice_candidates(
        struct rawrtc_ice_candidates** const candidatesp,
        struct odict* const dict,
        struct client* const client
) {
    size_t n;
    struct rawrtc_ice_candidates* candidates;
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;
    struct le* le;

    // Get length
    n = rawrtc_list_count(&dict->lst);

    // Allocate & set length immediately
    // Note: We allocate more than we need in case ICE candidate types are being filtered but... meh
    candidates = rawrtc_mem_zalloc(sizeof(*candidates) + (sizeof(struct rawrtc_ice_candidate*) * n),
                            ice_candidates_destroy);
    if (!candidates) {
        printf("No memory to allocate ICE candidates array");
    }
    candidates->n_candidates = 0;

    // Get ICE candidates
    for (le = rawrtc_list_head(&dict->lst); le != NULL; le = le->next) {
        struct odict* const node = ((struct odict_entry*) le->data)->u.odict;
        char const* type_str = NULL;
        enum rawrtc_ice_candidate_type type;
        char* foundation;
        uint32_t priority;
        char* ip;
        char const* protocol_str = NULL;
        enum rawrtc_ice_protocol protocol;
        uint16_t port;
        char const* tcp_type_str = NULL;
        enum rawrtc_ice_tcp_candidate_type tcp_type = RAWRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE;
        char* related_address = NULL;
        uint16_t related_port = 0;
        struct rawrtc_ice_candidate* candidate;

        // Get ICE candidate
        error |= dict_get_entry(&type_str, node, "type", ODICT_STRING, true);
        error |= rawrtc_str_to_ice_candidate_type(&type, type_str);
        error |= dict_get_entry(&foundation, node, "foundation", ODICT_STRING, true);
        error |= dict_get_uint32(&priority, node, "priority", true);
        error |= dict_get_entry(&ip, node, "ip", ODICT_STRING, true);
        error |= dict_get_entry(&protocol_str, node, "protocol", ODICT_STRING, true);
        error |= rawrtc_str_to_ice_protocol(&protocol, protocol_str);
        error |= dict_get_uint16(&port, node, "port", true);
        if (protocol == RAWRTC_ICE_PROTOCOL_TCP) {
            error |= dict_get_entry(&tcp_type_str, node, "tcpType", ODICT_STRING, true);
            error |= rawrtc_str_to_ice_tcp_candidate_type(&tcp_type, tcp_type_str);
        }
        dict_get_entry(&related_address, node, "relatedAddress", ODICT_STRING, false);
        dict_get_uint16(&related_port, node, "relatedPort", false);
        if (error) {
            goto out;
        }

        // Create and add ICE candidate
        error = rawrtc_ice_candidate_create(
                &candidate, foundation, priority, ip, protocol, port, type,
                tcp_type, related_address, related_port);
        if (error) {
            goto out;
        }
        // Print ICE candidate
        print_ice_candidate(candidate, NULL, client);
        // Store if ICE candidate type enabled
        if (ice_candidate_type_enabled(client, type)) {
            candidates->candidates[candidates->n_candidates++] = candidate;
        } else {
            rawrtc_mem_deref(candidate);
        }
    }

out:
    if (error) {
        rawrtc_mem_deref(candidates);
    } else {
        // Set pointer
        *candidatesp = candidates;
    }
    return error;
}

/*
 * Get DTLS parameters from dictionary.
 */
enum rawrtc_code get_dtls_parameters(
        struct rawrtc_dtls_parameters** const parametersp,
        struct odict* const dict
) {
    size_t n;
    struct rawrtc_dtls_parameters* parameters = NULL;
    struct rawrtc_dtls_fingerprints* fingerprints;
    enum rawrtc_code error;
    char const* role_str = NULL;
    enum rawrtc_dtls_role role;
    struct odict* node;
    struct le* le;
    size_t i;

    // Get fingerprints array and length
    error = dict_get_entry(&node, dict, "fingerprints", ODICT_ARRAY, true);
    if (error) {
        return error;
    }
    n = rawrtc_list_count(&node->lst);

    // Allocate & set length immediately
    fingerprints = rawrtc_mem_zalloc(
            sizeof(*fingerprints) + (sizeof(struct rawrtc_dtls_fingerprints*) * n),
            dtls_fingerprints_destroy);
    if (!fingerprints) {
        printf("No memory to allocate DTLS fingerprint array");
    }
    fingerprints->n_fingerprints = n;

    // Get role
    error |= dict_get_entry(&role_str, dict, "role", ODICT_STRING, true);
    error |= rawrtc_str_to_dtls_role(&role, role_str);
    if (error) {
        role = RAWRTC_DTLS_ROLE_AUTO;
    }

    // Get fingerprints
    for (le = rawrtc_list_head(&node->lst), i = 0; le != NULL; le = le->next, ++i) {
        node = ((struct odict_entry*) le->data)->u.odict;
        char* algorithm_str = NULL;
        enum rawrtc_certificate_sign_algorithm algorithm;
        char* value;

        // Get fingerprint
        error |= dict_get_entry(&algorithm_str, node, "algorithm", ODICT_STRING, true);
        error |= rawrtc_str_to_certificate_sign_algorithm(&algorithm, algorithm_str);
        error |= dict_get_entry(&value, node, "value", ODICT_STRING, true);
        if (error) {
            goto out;
        }

        // Create and add fingerprint
        error = rawrtc_dtls_fingerprint_create(&fingerprints->fingerprints[i], algorithm, value);
        if (error) {
            goto out;
        }
    }
    // Create DTLS parameters
    error = rawrtc_dtls_parameters_create(
            &parameters, role, fingerprints->fingerprints, fingerprints->n_fingerprints);

out:
    rawrtc_mem_deref(fingerprints);
    if (error) {
        rawrtc_mem_deref(parameters);
    } else {
        // Set pointer
        *parametersp = parameters;
    }
    return error;
}

/*
 * Get SCTP parameters from dictionary.
 */
enum rawrtc_code get_sctp_parameters(
        struct sctp_parameters* const parameters,
        struct odict* const dict
) {
    enum rawrtc_code error;
    uint64_t max_message_size;

    // Get maximum message size
    error = dict_get_entry(&max_message_size, dict, "maxMessageSize", ODICT_INT, true);
    if (error) {
        return error;
    }

    // Get port
    error = dict_get_uint16(&parameters->port, dict, "port", false);
    if (error && error != RAWRTC_CODE_NO_VALUE) {
        // Note: Nothing to do in NO VALUE case as port has been set to 0 by default
        return error;
    }

    // Create SCTP capabilities instance
    return rawrtc_sctp_capabilities_create(&parameters->capabilities, max_message_size);
}

/*
 * Set ICE parameters as string.
 */
void set_ice_parameters_string(
        struct rawrtc_ice_parameters* const parameters, char *str
) {
    char* username_fragment;
    char* password;
    bool ice_lite;

    // Get values
    if (rawrtc_ice_parameters_get_username_fragment(&username_fragment, parameters) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_parameters: usename fragment");
            exit (-1);
        }
    if (rawrtc_ice_parameters_get_password(&password, parameters) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_parameters: password");
            exit (-1);
        }
    if (rawrtc_ice_parameters_get_ice_lite(&ice_lite, parameters) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_parameters: ice lite");
            exit (-1);
        }
    sprintf(str, "\"iceParameters\":{\"usernameFragment\":\"%s\",\"password\":\"%s\",\"iceLite\":%s}",
        username_fragment, password, (ice_lite ? "true":"false"));

    // Un-reference values
    rawrtc_mem_deref(password);
    rawrtc_mem_deref(username_fragment);
}

/*
 * Set ICE candidates as string.
 */
void set_ice_candidates_string(
        struct rawrtc_ice_candidates* const parameters, char *candidates
) {
    size_t i;
    char *str = calloc(1, 512);

    sprintf(candidates, "\"iceCandidates\":[");

    // Set ICE candidates
    for (i = 0; i < parameters->n_candidates; ++i) {
      //  enum rawrtc_code error;
        struct rawrtc_ice_candidate* const candidate = parameters->candidates[i];
        char* foundation;
        uint32_t priority;
        char* ip;
        enum rawrtc_ice_protocol protocol;
        uint16_t port;
        enum rawrtc_ice_candidate_type type;
        enum rawrtc_ice_tcp_candidate_type tcp_type = RAWRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE;
        char* related_address = NULL;
        uint16_t related_port = 0;
       // char* key;

        if (i > 0) {
            strcat(candidates, ",");
        }

        // Get values
        if (rawrtc_ice_candidate_get_foundation(&foundation, candidate) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_candidate: foundation");
            exit (-1);
        }
        if (rawrtc_ice_candidate_get_priority(&priority, candidate) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_candidate: priority");
            exit (-1);
        }
        if (rawrtc_ice_candidate_get_ip(&ip, candidate) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_candidate: ip");
            exit (-1);
        }
        if (rawrtc_ice_candidate_get_protocol(&protocol, candidate) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_candidate: protocol");
            exit (-1);
        }
        if (rawrtc_ice_candidate_get_port(&port, candidate) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_candidate: port");
            exit (-1);
        }
        if (rawrtc_ice_candidate_get_type(&type, candidate) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_candidate: type");
            exit (-1);
        }
        rawrtc_ice_candidate_get_tcp_type(&tcp_type, candidate);
        rawrtc_ice_candidate_get_related_address(&related_address, candidate);
        rawrtc_ice_candidate_get_related_port(&related_port, candidate);

        sprintf(str, "{\"foundation\":\"%s\",\"priority\":%i,\"ip\":\"%s\",\"protocol\":\"%s\",\"port\":%d,\"type\":\"%s\"",
            foundation, priority, ip, rawrtc_ice_protocol_to_str(protocol), port, rawrtc_ice_candidate_type_to_str(type));


        if (protocol == RAWRTC_ICE_PROTOCOL_TCP) {
            sprintf(str, "%s,\"tcpType\":\"%s\"", str, rawrtc_ice_tcp_candidate_type_to_str(tcp_type));
        }

        char st[50];
        if (related_address) {
            sprintf(st, ",\"relatedAddress\":\"%s\"", related_address);
            strcat(str, st);
        }

        if (related_port) {
            sprintf(st, ",\"relatedPort\":%d", related_port);
            strcat(str, st);
        }
        strcat(str, "}");
        printf("Ice Candidate: %s\n", str);

        strcat(candidates, str);
        // Un-reference values
        rawrtc_mem_deref(related_address);
        rawrtc_mem_deref(ip);
        rawrtc_mem_deref(foundation);
    }
    strcat(candidates, "]");
    free (str);
}

/*
 * Set DTLS parameters as string.
 */
void set_dtls_parameters_string(
        struct rawrtc_dtls_parameters* const parameters, char *params
) {
    enum rawrtc_dtls_role role;
    struct rawrtc_dtls_fingerprints* fingerprints;
    size_t i;
    char *str = calloc(1, 512);

    sprintf(params, "\"dtlsParameters\":");

    // Get and set DTLS role
    if (rawrtc_dtls_parameters_get_role(&role, parameters) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_dtls_parameters: get role");
        exit (-1);
    }
    char st[50];
    sprintf(st, "{\"role\":\"%s\"", rawrtc_dtls_role_to_str(role));
    strcat(params, st);
   // sprintf(params, "%s{\"role\":\"%s\"", params, rawrtc_dtls_role_to_str(role));

    // Get and set fingerprints
    if (rawrtc_dtls_parameters_get_fingerprints(&fingerprints, parameters) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_dtls_parameters: get fingerprints");
        exit (-1);
    }
    strcat(params, ",\"fingerprints\":[");
    for (i = 0; i < parameters->fingerprints->n_fingerprints; ++i) {
        struct rawrtc_dtls_fingerprint* const fingerprint =
                parameters->fingerprints->fingerprints[i];
        enum rawrtc_certificate_sign_algorithm sign_algorithm;
        char* value;

        // Get values
        if (rawrtc_dtls_parameters_fingerprint_get_sign_algorithm(&sign_algorithm, fingerprint) != RAWRTC_CODE_SUCCESS) {
            printf("Error set_dtls_parameters: get sign_algorithm");
            exit (-1);
        }
        if (rawrtc_dtls_parameters_fingerprint_get_value(&value, fingerprint) != RAWRTC_CODE_SUCCESS) {
            printf("Error set_dtls_parameters: get value");
            exit (-1);
        }

        sprintf(str, "{\"algorithm\":\"%s\",\"value\":\"%s\"}",
            rawrtc_certificate_sign_algorithm_to_str(sign_algorithm),
            value);

        if (i > 0) {
            strcat(params, ",");
        }
        strcat(params, str);

        // Un-reference values
        rawrtc_mem_deref(value);
    }
    strcat(params, "]}");
    // Un-reference fingerprints
    rawrtc_mem_deref(fingerprints);
    free (str);
}

/*
 * Set SCTP parameters as string.
 */
void set_sctp_parameters_string(
        struct rawrtc_sctp_transport* const transport,
        struct sctp_parameters* const parameters, char *str
) {
    uint64_t max_message_size;
    uint16_t port;

    // Get values
    if (rawrtc_sctp_capabilities_get_max_message_size(&max_message_size, parameters->capabilities) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_sctp_parameters: get max_message_size");
        exit (-1);
    }
    if (rawrtc_sctp_transport_get_port(&port, transport) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_sctp_parameters: get port");
        exit (-1);
    }

    sprintf(str, "\"sctpParameters\":{\"maxMessageSize\":%lu,\"port\":%d}", max_message_size, port);
}


/*
 * Set ICE parameters in dictionary.
 */
void set_ice_parameters(
        struct rawrtc_ice_parameters* const parameters,
        struct odict* const dict
) {
    char* username_fragment;
    char* password;
    bool ice_lite;

    // Get values
    if (rawrtc_ice_parameters_get_username_fragment(&username_fragment, parameters) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_parameters: usename fragment");
            exit (-1);
        }
    if (rawrtc_ice_parameters_get_password(&password, parameters) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_parameters: password");
            exit (-1);
        }
    if (rawrtc_ice_parameters_get_ice_lite(&ice_lite, parameters) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_parameters: ice lite");
            exit (-1);
        }

    // Set ICE parameters
    if (rawrtc_odict_entry_add(dict, "usernameFragment", ODICT_STRING, username_fragment) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_parameters: add usernameFragment");
            exit (-1);
        }
    if (rawrtc_odict_entry_add(dict, "password", ODICT_STRING, password) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_parameters: add passowrd");
            exit (-1);
        }
    if (rawrtc_odict_entry_add(dict, "iceLite", ODICT_BOOL, ice_lite) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_parameters: add ice lite");
            exit (-1);
        }

    // Un-reference values
    rawrtc_mem_deref(password);
    rawrtc_mem_deref(username_fragment);
}

/*
 * Set ICE candidates in dictionary.
 */
void set_ice_candidates(
        struct rawrtc_ice_candidates* const parameters,
        struct odict* const array
) {
    size_t i;
    struct odict* node;

    // Set ICE candidates
    for (i = 0; i < parameters->n_candidates; ++i) {
      //  enum rawrtc_code error;
        struct rawrtc_ice_candidate* const candidate = parameters->candidates[i];
        char* foundation;
        uint32_t priority;
        char* ip;
        enum rawrtc_ice_protocol protocol;
        uint16_t port;
        enum rawrtc_ice_candidate_type type;
        enum rawrtc_ice_tcp_candidate_type tcp_type = RAWRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE;
        char* related_address = NULL;
        uint16_t related_port = 0;
        char* key;

        // Create object
        rawrtc_odict_alloc(&node, 16);

        // Get values
        if (rawrtc_ice_candidate_get_foundation(&foundation, candidate) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_candidate: foundation");
            exit (-1);
        }
        if (rawrtc_ice_candidate_get_priority(&priority, candidate) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_candidate: priority");
            exit (-1);
        }
        if (rawrtc_ice_candidate_get_ip(&ip, candidate) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_candidate: ip");
            exit (-1);
        }
        if (rawrtc_ice_candidate_get_protocol(&protocol, candidate) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_candidate: protocol");
            exit (-1);
        }
        if (rawrtc_ice_candidate_get_port(&port, candidate) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_candidate: port");
            exit (-1);
        }
        if (rawrtc_ice_candidate_get_type(&type, candidate) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_candidate: type");
            exit (-1);
        }
        rawrtc_ice_candidate_get_tcp_type(&tcp_type, candidate);
        rawrtc_ice_candidate_get_related_address(&related_address, candidate);
        rawrtc_ice_candidate_get_related_port(&related_port, candidate);

        // Set ICE candidate values
        rawrtc_odict_entry_add(node, "foundation", ODICT_STRING, foundation);
        rawrtc_odict_entry_add(node, "priority", ODICT_INT, priority);
        rawrtc_odict_entry_add(node, "ip", ODICT_STRING, ip);
        rawrtc_odict_entry_add(node, "protocol", ODICT_STRING, rawrtc_ice_protocol_to_str(protocol));
        rawrtc_odict_entry_add(node, "port", ODICT_INT, port);
        rawrtc_odict_entry_add(node, "type", ODICT_STRING, rawrtc_ice_candidate_type_to_str(type));
        if (protocol == RAWRTC_ICE_PROTOCOL_TCP) {
            rawrtc_odict_entry_add(node, "tcpType", ODICT_STRING,
                                rawrtc_ice_tcp_candidate_type_to_str(tcp_type));
        }
        if (related_address) {
            rawrtc_odict_entry_add(node, "relatedAddress", ODICT_STRING, related_address);
        }
        if (related_port) {
            rawrtc_odict_entry_add(node, "relatedPort", ODICT_INT, related_port);
        }

        // Add to array
        if (rawrtc_sdprintf(&key, "%zu", i) != RAWRTC_CODE_SUCCESS)              {
            printf("Error set_ice_candidate: key");
            exit (-1);
        }
        rawrtc_odict_entry_add(array, key, ODICT_OBJECT, node);

        // Un-reference values
        rawrtc_mem_deref(key);
        rawrtc_mem_deref(related_address);
        rawrtc_mem_deref(ip);
        rawrtc_mem_deref(foundation);
        rawrtc_mem_deref(node);
    }
}

/*
 * Set DTLS parameters in dictionary.
 */
void set_dtls_parameters(
        struct rawrtc_dtls_parameters* const parameters,
        struct odict* const dict
) {
    enum rawrtc_dtls_role role;
    struct odict* array;
    struct odict* node;
    struct rawrtc_dtls_fingerprints* fingerprints;
    size_t i;

    // Get and set DTLS role
    if (rawrtc_dtls_parameters_get_role(&role, parameters) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_dtls_parameters: get role");
        exit (-1);
    }
    if (rawrtc_odict_entry_add(dict, "role", ODICT_STRING, rawrtc_dtls_role_to_str(role)) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_dtls_parameters: set role");
        exit (-1);
    }

    // Create array
    rawrtc_odict_alloc(&array, 16);

    // Get and set fingerprints
    if (rawrtc_dtls_parameters_get_fingerprints(&fingerprints, parameters) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_dtls_parameters: get fingerprints");
        exit (-1);
    }
    for (i = 0; i < parameters->fingerprints->n_fingerprints; ++i) {
        struct rawrtc_dtls_fingerprint* const fingerprint =
                parameters->fingerprints->fingerprints[i];
        enum rawrtc_certificate_sign_algorithm sign_algorithm;
        char* value;
        char* key;

        // Create object
        rawrtc_odict_alloc(&node, 16);

        // Get values
        if (rawrtc_dtls_parameters_fingerprint_get_sign_algorithm(&sign_algorithm, fingerprint) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_dtls_parameters: get sign_algorithm");
        exit (-1);
    }
        if (rawrtc_dtls_parameters_fingerprint_get_value(&value, fingerprint) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_dtls_parameters: get value");
        exit (-1);
    }

        // Set fingerprint values
        if (rawrtc_odict_entry_add(node, "algorithm", ODICT_STRING,  rawrtc_certificate_sign_algorithm_to_str(sign_algorithm)) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_dtls_parameters: add algorithm");
    }
        if (rawrtc_odict_entry_add(node, "value", ODICT_STRING, value) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_dtls_parameters: add value");
    }

        // Add to array
        rawrtc_sdprintf(&key, "%zu", i);
        if (rawrtc_odict_entry_add(array, key, ODICT_OBJECT, node) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_dtls_parameters: add key");
    }

        // Un-reference values
        rawrtc_mem_deref(key);
        rawrtc_mem_deref(value);
        rawrtc_mem_deref(node);
    }

    // Un-reference fingerprints
    rawrtc_mem_deref(fingerprints);

    // Add array to object
    if (rawrtc_odict_entry_add(dict, "fingerprints", ODICT_ARRAY, array) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_dtls_parameters: add array");
    }
    rawrtc_mem_deref(array);
}

/*
 * Set SCTP parameters in dictionary.
 */
void set_sctp_parameters(
        struct rawrtc_sctp_transport* const transport,
        struct sctp_parameters* const parameters,
        struct odict* const dict
) {
    uint64_t max_message_size;
    uint16_t port;

    // Get values
    if (rawrtc_sctp_capabilities_get_max_message_size(&max_message_size, parameters->capabilities) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_sctp_parameters: get max_message_size");
        exit (-1);
    }
    if (rawrtc_sctp_transport_get_port(&port, transport) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_sctp_parameters: get port");
        exit (-1);
    }

    // Set ICE parameters
    if (rawrtc_odict_entry_add(dict, "maxMessageSize", ODICT_INT, max_message_size) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_sctp_parameters: add max_message_size");
    }
    if (rawrtc_odict_entry_add(dict, "port", ODICT_INT, port) != RAWRTC_CODE_SUCCESS)              {
        printf("Error set_sctp_parameters: add array");
    }
}

/*
 * Get the ICE role from a string.
 */
enum rawrtc_code get_ice_role(
        enum rawrtc_ice_role* const rolep, // de-referenced
        uint8_t role
      //  char const* const str
) {
    // Get ICE role
  //  switch (str[0]) {
  	switch (role) {
        case 0:
            *rolep = RAWRTC_ICE_ROLE_CONTROLLED;
            return RAWRTC_CODE_SUCCESS;
        case 1:
            *rolep = RAWRTC_ICE_ROLE_CONTROLLING;
            return RAWRTC_CODE_SUCCESS;
        default:
            return RAWRTC_CODE_INVALID_ARGUMENT;
    }
}

/*
 * Get a uint32 entry and store it in `*valuep`.
 */
enum rawrtc_code dict_get_uint32(
        uint32_t* const valuep,
        struct odict* const parent,
        char* const key,
        bool required
) {
    int64_t value;

    // Check arguments
    if (!valuep || !parent || !key) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get int64_t
    enum rawrtc_code error = dict_get_entry(&value, parent, key, ODICT_INT, required);
    if (error) {
        return error;
    }

    // Check bounds
    if (value < 0 || value > UINT32_MAX) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set value & done
    *valuep = (uint32_t) value;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get a uint16 entry and store it in `*valuep`.
 */
enum rawrtc_code dict_get_uint16(
        uint16_t* const valuep,
        struct odict* const parent,
        char* const key,
        bool required
) {
    int64_t value;

    // Check arguments
    if (!valuep || !parent || !key) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get int64_t
    enum rawrtc_code error = dict_get_entry(&value, parent, key, ODICT_INT, required);
    if (error) {
        return error;
    }

    // Check bounds
    if (value < 0 || value > UINT16_MAX) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set value & done
    *valuep = (uint16_t) value;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Create a data channel helper instance from parameters.
 */
void data_channel_helper_create_from_channel(
        struct data_channel_helper** const channel_helperp, // de-referenced
        struct rawrtc_data_channel* channel,
        struct client* const client,
        void* const arg // nullable
) {
    enum rawrtc_code error;
    struct rawrtc_data_channel_parameters* parameters;
    char* label;

    // Allocate
    struct data_channel_helper* const channel_helper =
            rawrtc_mem_zalloc(sizeof(*channel_helper), data_channel_helper_destroy);
    if (!channel_helper) {
        printf("RAWRTC_CODE_NO_MEMORY\n");
        return;
    }
    // Get parameters
    if (rawrtc_data_channel_get_parameters(&parameters, channel) != RAWRTC_CODE_SUCCESS)              {
            printf("Could not get channel parameters");
            exit (-1);
        }

    // Get & set label
    error = rawrtc_data_channel_parameters_get_label(&label, parameters);
    switch (error) {
        case RAWRTC_CODE_SUCCESS:
            if (rawrtc_strdup(&channel_helper->label, label) != RAWRTC_CODE_SUCCESS)              {
            printf("Could not copy label");
            exit (-1);
        }
            rawrtc_mem_deref(label);
            break;
        case RAWRTC_CODE_NO_VALUE:
            if (rawrtc_strdup(&channel_helper->label, "N/A") != RAWRTC_CODE_SUCCESS)              {
            printf("Could not copy label");
            exit (-1);
        }
            break;
        default:
            printf("error\n");
    }

    // Set fields
    channel_helper->client = client;
    channel_helper->channel = channel;
    channel_helper->arg = rawrtc_mem_ref(arg);

    // Set pointer
    *channel_helperp = channel_helper;
    // Un-reference & done
    rawrtc_mem_deref(parameters);
}

#endif
