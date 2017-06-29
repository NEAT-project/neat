#include <stdio.h>

#if defined(WEBRTC_SUPPORT)
#include "neat.h"
#include "neat_internal.h"
#include "neat_webrtc_tools.h"
#include <rawrtc.h>
#include <unistd.h>

#define STDIN_FILENO 0

#define ARRAY_SIZE(a) ((sizeof(a))/(sizeof((a)[0])))

struct rawrtc_flow;

struct rawrtc_ice_gatherer* gatherer;
static int done = 0;
//static neat_flow *n_flow = NULL;

//static uv_timer_t *timer_handle = NULL;

static void data_channel_open_handler(
        void* const arg
);

static void client_stop(
        struct peer_connection* const client
);

static struct peer_connection peer;

static void client_set_parameters(
        struct peer_connection* const client
) {
    struct parameters* const remote_parameters = &client->remote_parameters;
printf("client_set_parameters: remote numcandidates=%zu\n", remote_parameters->ice_candidates->n_candidates);
    // Set remote ICE candidates
    if (rawrtc_ice_transport_set_remote_candidates(
            client->ice_transport, remote_parameters->ice_candidates->candidates,
            remote_parameters->ice_candidates->n_candidates) != RAWRTC_CODE_SUCCESS) {
        printf("Error setting client parameters \n");
        exit (-1);
    }
}

void transport_upcall_handler(
        struct socket* socket,
        void* arg,
        int flags
) {
    printf("%s\n", __func__);
    int event = webrtc_upcall_handler(socket, arg, flags);
    printf("after webrtc_upcall_handler: event=%d arg=rawrtc_sctp_transport=%p\n", event, (void *)arg);
    if (event == SCTP_EVENT_WRITE) {
        struct rawrtc_sctp_transport* const transport = arg;
        printf("arg of rawrtc_sctp_transport = peer_connection %p\n", (void *)transport->arg);
        struct peer_connection* const client = transport->arg;
        printf("n_flows=%zu\n", client->n_flows);
        for (int i = 0; i < (int)client->max_flows; i++) {
            if (client->flows[i]->state == NEAT_FLOW_OPEN && client->flows[i]->flow->operations && client->flows[i]->flow->operations->on_writable) {
                webrtc_io_writable(client->ctx, client->flows[i]->flow, NEAT_OK);
            }
        }
    }
}

static void client_start_transports(
        struct peer_connection* const client
) {
    struct parameters* const remote_parameters = &client->remote_parameters;

    // Start ICE transport
    if (rawrtc_ice_transport_start(
            client->ice_transport, client->gatherer, remote_parameters->ice_parameters,
            client->role) != RAWRTC_CODE_SUCCESS) {
        printf("Error starting ice transport \n");
        exit (-1);
    }

    // Start DTLS transport
    if (rawrtc_dtls_transport_start(
            client->dtls_transport, remote_parameters->dtls_parameters) != RAWRTC_CODE_SUCCESS) {
        printf("Error starting dtls transport \n");
        exit (-1);
    }

    // Start SCTP transport
    if (rawrtc_sctp_transport_start(
            client->sctp_transport, remote_parameters->sctp_parameters.capabilities,
            remote_parameters->sctp_parameters.port) != RAWRTC_CODE_SUCCESS) {
        printf("Error starting SCTP transport \n");
        exit (-1);
    }
    printf("sctp_transport=%p\n", (void *)client->sctp_transport);
}

static void parse_param_from_signaling_server(struct neat_ctx *ctx, struct neat_flow *flow, char* params)
{
    struct peer_connection* const client = &peer;
    enum rawrtc_code error;
    struct odict* dict = NULL;
    struct odict* node = NULL;
    struct rawrtc_ice_parameters* ice_parameters = NULL;
    struct rawrtc_ice_candidates* ice_candidates = NULL;
    struct rawrtc_dtls_parameters* dtls_parameters = NULL;
    struct sctp_parameters sctp_parameters;

printf("%s\n", __func__);
    // Get dict from JSON
    error = get_json_buffer(&dict, params);
    if (error) {
        goto out;
    }

    // Decode JSON
    error |= dict_get_entry(&node, dict, "iceParameters", ODICT_OBJECT, true);
    error |= get_ice_parameters(&ice_parameters, node);
    error |= dict_get_entry(&node, dict, "iceCandidates", ODICT_ARRAY, true);
    error |= get_ice_candidates(&ice_candidates, node, (void *)client);
    error |= dict_get_entry(&node, dict, "dtlsParameters", ODICT_OBJECT, true);
    error |= get_dtls_parameters(&dtls_parameters, node);
    error |= dict_get_entry(&node, dict, "sctpParameters", ODICT_OBJECT, true);
    error |= get_sctp_parameters(&sctp_parameters, node);

    // Ok?
    if (error) {
        printf("Invalid remote parameters\n");
        if (sctp_parameters.capabilities) {
            rawrtc_mem_deref(sctp_parameters.capabilities);
        }
        goto out;
    }
printf("ice_candidates->n_candidates=%zu\n", ice_candidates->n_candidates);
    // Set parameters & start transports
    client->remote_parameters.ice_parameters = rawrtc_mem_ref(ice_parameters);
    client->remote_parameters.ice_candidates = rawrtc_mem_ref(ice_candidates);
    client->remote_parameters.dtls_parameters = rawrtc_mem_ref(dtls_parameters);
    memcpy(&client->remote_parameters.sctp_parameters, &sctp_parameters, sizeof(sctp_parameters));
    printf("Applying remote parameters\n");
    client_set_parameters(client);
    client_start_transports(client);

out:
    // Un-reference
    rawrtc_mem_deref(dtls_parameters);
    rawrtc_mem_deref(ice_candidates);
    rawrtc_mem_deref(ice_parameters);
    rawrtc_mem_deref(dict);

    // Exit?
    if (error == RAWRTC_CODE_NO_VALUE) {
        printf("Exiting\n");

        // Stop client & bye
        client_stop(client);

        printf("close rawrtc\n");
        rawrtc_close();
        printf("rawrtc_closed\n");
        for (int i = 0; i < (int)client->n_flows; i++) {
            neat_close(client->ctx, client->flows[i]->flow);
        }
    }

}

static void parse_remote_parameters(
        int flags,
        void* arg
) {
    struct peer_connection* const client = arg;
    enum rawrtc_code error;
    struct odict* dict = NULL;
    struct odict* node = NULL;
    struct rawrtc_ice_parameters* ice_parameters = NULL;
    struct rawrtc_ice_candidates* ice_candidates = NULL;
    struct rawrtc_dtls_parameters* dtls_parameters = NULL;
    struct sctp_parameters sctp_parameters;
    (void) flags;
printf("%s\n", __func__);
    // Get dict from JSON
    error = get_json_stdin(&dict);
    if (error) {
        goto out;
    }

    // Decode JSON
    error |= dict_get_entry(&node, dict, "iceParameters", ODICT_OBJECT, true);
    error |= get_ice_parameters(&ice_parameters, node);
    error |= dict_get_entry(&node, dict, "iceCandidates", ODICT_ARRAY, true);
    error |= get_ice_candidates(&ice_candidates, node, arg);
    error |= dict_get_entry(&node, dict, "dtlsParameters", ODICT_OBJECT, true);
    error |= get_dtls_parameters(&dtls_parameters, node);
    error |= dict_get_entry(&node, dict, "sctpParameters", ODICT_OBJECT, true);
    error |= get_sctp_parameters(&sctp_parameters, node);

    // Ok?
    if (error) {
        printf("Invalid remote parameters\n");
        if (sctp_parameters.capabilities) {
            rawrtc_mem_deref(sctp_parameters.capabilities);
        }
        goto out;
    }
printf("ice_candidates->n_candidates=%zu\n", ice_candidates->n_candidates);
    // Set parameters & start transports
    client->remote_parameters.ice_parameters = rawrtc_mem_ref(ice_parameters);
    client->remote_parameters.ice_candidates = rawrtc_mem_ref(ice_candidates);
    client->remote_parameters.dtls_parameters = rawrtc_mem_ref(dtls_parameters);
    memcpy(&client->remote_parameters.sctp_parameters, &sctp_parameters, sizeof(sctp_parameters));
    printf("Applying remote parameters\n");
    client_set_parameters(client);
    client_start_transports(client);

out:
    // Un-reference
    rawrtc_mem_deref(dtls_parameters);
    rawrtc_mem_deref(ice_candidates);
    rawrtc_mem_deref(ice_parameters);
    rawrtc_mem_deref(dict);

    // Exit?
    if (error == RAWRTC_CODE_NO_VALUE) {
        printf("Exiting\n");

        // Stop client & bye
        client_stop(client);

        printf("close rawrtc\n");
        rawrtc_close();
        printf("rawrtc_closed\n");
        for (int i = 0; i < (int)client->n_flows; i++) {
            neat_close(client->ctx, client->flows[i]->flow);
        }
    }
}

static void parameters_destroy(
        struct parameters* const parameters
) {
printf("%s\n", __func__);
    // Un-reference
    parameters->ice_parameters = rawrtc_mem_deref(parameters->ice_parameters);
    parameters->ice_candidates = rawrtc_mem_deref(parameters->ice_candidates);
    parameters->dtls_parameters = rawrtc_mem_deref(parameters->dtls_parameters);
    if (parameters->sctp_parameters.capabilities) {
        parameters->sctp_parameters.capabilities =
                rawrtc_mem_deref(parameters->sctp_parameters.capabilities);
    }
}

static void close_all_channels(struct peer_connection* const client)
{
    for (int i = 0; i < (int)client->n_flows; i++) {
        if (rawrtc_data_channel_close(client->flows[i]->channel) != RAWRTC_CODE_SUCCESS) {
            printf("%s could not be closed \n", client->flows[i]->label);
        }
        printf("deref channel\n");
        rawrtc_mem_deref(client->flows[i]->channel);
    }
}


static void client_stop(
        struct peer_connection* const client
) {
printf("%s\n", __func__);
        // Stop transports & close gatherer
    // Clear data channels
    rawrtc_list_flush(&client->data_channels);
printf("%s:%d\n", __func__, __LINE__);
    close_all_channels(client);
printf("%s:%d\n", __func__, __LINE__);
    if (rawrtc_sctp_transport_stop(client->sctp_transport) != RAWRTC_CODE_SUCCESS) {
        printf("Error stopping sctp transport \n");
        exit (-1);
    }
    printf("%s:%d\n", __func__, __LINE__);
    if (rawrtc_dtls_transport_stop(client->dtls_transport) != RAWRTC_CODE_SUCCESS) {
        printf("Error stopping dtls transport \n");
        exit (-1);
    }
    printf("%s:%d\n", __func__, __LINE__);
    if (rawrtc_ice_transport_stop(client->ice_transport) != RAWRTC_CODE_SUCCESS) {
        printf("Error stopping ice transport \n");
        exit (-1);
    }
    printf("%s:%d\n", __func__, __LINE__);
    if (rawrtc_ice_gatherer_close(client->gatherer) != RAWRTC_CODE_SUCCESS) {
        printf("Error closing gatherer\n");
        exit (-1);
    }
printf("%s:%d\n", __func__, __LINE__);
    // Un-reference & close
    parameters_destroy(&client->remote_parameters);
    printf("%s:%d\n", __func__, __LINE__);
    parameters_destroy(&client->local_parameters);
    printf("%s:%d\n", __func__, __LINE__);
    client->data_transport = rawrtc_mem_deref(client->data_transport);
    printf("%s:%d\n", __func__, __LINE__);
    client->sctp_transport = rawrtc_mem_deref(client->sctp_transport);
    printf("%s:%d\n", __func__, __LINE__);
    client->dtls_transport = rawrtc_mem_deref(client->dtls_transport);
    printf("%s:%d\n", __func__, __LINE__);
    client->ice_transport = rawrtc_mem_deref(client->ice_transport);
    printf("%s:%d\n", __func__, __LINE__);
    client->gatherer = rawrtc_mem_deref(client->gatherer);
    printf("%s:%d\n", __func__, __LINE__);
    client->certificate = rawrtc_mem_deref(client->certificate);
    printf("%s:%d\n", __func__, __LINE__);
    client->gather_options = rawrtc_mem_deref(client->gather_options);
    printf("%s:%d\n", __func__, __LINE__);
}

/*
 * Print the data channel's received message's size and echo the
 * message back.
 */
void data_channel_message_handler(
        struct mbuf* const buffer,
        enum rawrtc_data_channel_message_flag const flags,
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct peer_connection* const client =
            (struct peer_connection*) channel->client;
  /*  enum rawrtc_code error;*/
    (void) flags;
printf("%s: arg=data_channel_helper\n", __func__);
    // Print message size
    default_data_channel_message_handler(buffer, flags, arg);
    for (int i = 0; i < (int)client->n_flows; i++) {
    printf("compare %s with %s\n", client->flows[i]->label, channel->label);
        if (!strcmp(client->flows[i]->label, channel->label)) {
        printf("found! call io_readable\n");
           webrtc_io_readable(client->ctx, client->flows[i]->flow, NEAT_OK, (void *)buffer->buf, buffer->end);
           break;
        }
    }
}

void data_channel_close_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct peer_connection* const client = (struct peer_connection *)channel->client;

    default_data_channel_close_handler(arg);
    printf("%s for channel with label %s\n", __func__, channel->label);

    for (int i = 0; i < (int)client->max_flows; i++) {
    printf("%s: label=%s state=%d\n", __func__, client->flows[i]->label, client->flows[i]->state);
        if ((client->flows[i]->state != NEAT_FLOW_CLOSED) && (!strcmp(client->flows[i]->label, channel->label))) {
            client->flows[i]->state = NEAT_FLOW_CLOSED;
            client->n_flows--;
            printf("call neat_notify_close for %s\n", client->flows[i]->label);
            neat_notify_close(client->flows[i]->flow);
        }
    }
    if (!done && client->n_flows == 0) {
        done = 1;
        client_stop(client);
        rawrtc_close();
        printf("close listening flow\n");
        neat_notify_close(client->listening_flow);
    }
}

/*
 * Handle the newly created data channel.
 */
void data_channel_handler(
        struct rawrtc_data_channel* const channel, // read-only, MUST be referenced when used
        void* const arg // will be casted to `struct client*`
) {
    struct peer_connection* const client = arg;
    struct data_channel_helper* channel_helper;
printf("%s: arg= peer_connection\n", __func__);
    // Print channel
    default_data_channel_handler(channel, arg);

    // Create data channel helper instance & add to list
    // Note: In this case we need to reference the channel because we have not created it
    data_channel_helper_create_from_channel(&channel_helper, rawrtc_mem_ref(channel), arg, NULL);
    rawrtc_list_append(&client->data_channels, &channel_helper->le, channel_helper);

    // Set handler argument & handlers
    if (rawrtc_data_channel_set_arg(channel, channel_helper) != RAWRTC_CODE_SUCCESS)              {
        neat_log(client->ctx, NEAT_LOG_ERROR, "Could not set arg");
        exit (-1);
    }
    if (rawrtc_data_channel_set_open_handler(channel, default_data_channel_open_handler) != RAWRTC_CODE_SUCCESS) {
        neat_log(client->ctx, NEAT_LOG_ERROR, "Could not open handler");
        exit (-1);
    }
    if (rawrtc_data_channel_set_buffered_amount_low_handler(
            channel, default_data_channel_buffered_amount_low_handler)!= RAWRTC_CODE_SUCCESS) {
        neat_log(client->ctx, NEAT_LOG_ERROR, "Could not set buffered amount low");
        exit (-1);
    }
    if (rawrtc_data_channel_set_error_handler(channel, default_data_channel_error_handler)!= RAWRTC_CODE_SUCCESS) {
        neat_log(client->ctx, NEAT_LOG_ERROR, "Could not set error handler");
        exit (-1);
    }
    if (rawrtc_data_channel_set_close_handler(channel, data_channel_close_handler)!= RAWRTC_CODE_SUCCESS) {
        neat_log(client->ctx, NEAT_LOG_ERROR, "Could not set close handler");
        exit (-1);
    }
    if (rawrtc_data_channel_set_message_handler(channel, data_channel_message_handler)!= RAWRTC_CODE_SUCCESS) {
        neat_log(client->ctx, NEAT_LOG_ERROR, "Could not set message handler");
        exit (-1);
    }
    struct neat_flow *newFlow = neat_new_flow(client->ctx);
    newFlow->state = NEAT_FLOW_OPEN;

    newFlow->operations = calloc (1, sizeof(struct neat_flow_operations));
    if (newFlow->operations == NULL) {
        neat_io_error(client->ctx, newFlow, NEAT_ERROR_OUT_OF_MEMORY);
        return;
    }

    newFlow->operations->on_connected   = client->listening_flow->operations->on_connected;
    newFlow->operations->on_readable    = client->listening_flow->operations->on_readable;
    newFlow->operations->on_writable    = client->listening_flow->operations->on_writable;
    newFlow->operations->on_close       = client->listening_flow->operations->on_close;
    newFlow->operations->on_error       = client->listening_flow->operations->on_error;
    newFlow->operations->ctx            = client->ctx;
    newFlow->operations->flow           = client->listening_flow;
    newFlow->operations->userData       = client->listening_flow->operations->userData;
    newFlow->peer_connection            = client;
    newFlow->webrtcEnabled              = true;
    newFlow->operations->label = strdup(channel_helper->label);
    struct rawrtc_flow* r_flow = calloc(1, sizeof(struct rawrtc_flow));
    r_flow->flow = newFlow;
    r_flow->state = NEAT_FLOW_OPEN;
    r_flow->label = strdup(channel_helper->label);
    r_flow->channel = rawrtc_mem_ref(channel);
    client->flows[client->n_flows] = r_flow;
    client->n_flows++;
    client->max_flows++;

    webrtc_io_connected(client->ctx, newFlow, NEAT_OK);
       // client->active_flow->peer_connection = client;
}


static void sctp_transport_state_change_handler(
    enum rawrtc_sctp_transport_state const state,
    void* const arg
) {
    struct peer_connection* const client = arg;
    enum rawrtc_dtls_role role;
printf("%s: arg=peer_connection\n", __func__);
    // Print state
    default_sctp_transport_state_change_handler(state, arg);

    // Open?
    if (state == RAWRTC_SCTP_TRANSPORT_STATE_CONNECTED) {
      //  client->active_flow->state = NEAT_FLOW_OPEN;

        for (int i = 0; i < (int)client->max_flows; i++) {
            if (client->flows[i]->state == NEAT_FLOW_WAITING) {
                struct rawrtc_data_channel_parameters* channel_parameters;
                struct data_channel_helper* data_channel_negotiated;

                if (client->flows[i]->flow->operations && client->flows[i]->flow->operations->on_connected) {
            client->flows[i]->flow->peer_connection = client;
            webrtc_io_connected(client->ctx, client->flows[i]->flow, NEAT_OK);
        }

                // Create data channel helper
                data_channel_helper_create(
                    &data_channel_negotiated, (struct peer_connection *) arg, client->flows[i]->label);

                // Create data channel parameters
                if (rawrtc_data_channel_parameters_create(
                    &channel_parameters, data_channel_negotiated->label,
                    RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_UNORDERED, 0, NULL, false, 0)  != RAWRTC_CODE_SUCCESS)              {
                    neat_log(client->ctx, NEAT_LOG_ERROR, "Could not create channel parameters parameters");
                    exit (-1);
                }
                printf("call rawrtc_data_channel_create for flow %d\n", i);
                if (rawrtc_data_channel_create(
                    &data_channel_negotiated->channel, client->data_transport,
                    channel_parameters, NULL,
                    default_data_channel_open_handler,
                    default_data_channel_buffered_amount_low_handler,
                    default_data_channel_error_handler,
                    data_channel_close_handler,
                    data_channel_message_handler,
                    data_channel_negotiated) != RAWRTC_CODE_SUCCESS) {
                    neat_log(client->ctx, NEAT_LOG_ERROR, "Error creating data channel");
                    exit (-1);
                } else {
                    neat_log(client->ctx, NEAT_LOG_DEBUG, "Created data channel successfully");
                }

                if (rawrtc_dtls_parameters_get_role(&role, client->local_parameters.dtls_parameters) != RAWRTC_CODE_SUCCESS) {
                    neat_log(client->ctx, NEAT_LOG_ERROR, "Could not get role");
                    exit (-1);
                }
              //  client->active_flow->peer_connection = client;
                client->flows[i]->state = NEAT_FLOW_OPEN;
                client->flows[i]->channel = rawrtc_mem_ref(data_channel_negotiated->channel);
                client->flows[i]->flow->peer_connection = client;
                client->flows[i]->flow->operations->label = strdup(client->flows[i]->label);

                // Un-reference
                rawrtc_mem_deref(channel_parameters);
            }
        }
    }
 /*   if (state == RAWRTC_SCTP_TRANSPORT_STATE_CLOSED) {
    printf("max_flows=%d\n", client->max_flows);
        for (int i = (int)client->max_flows - 1; i >= 0; i--) {
            printf("i=%d state = %d \n", i, client->flows[i]->state);
            printf("%s:%d\n", __func__, __LINE__);
                neat_notify_close(client->flows[i]->flow);
                printf("nach neat_notify_close\n");
            client->n_flows--;
            free(client->flows[i]);
            printf("nach free \n");
        }
    }*/
}


/*
 * Print the ICE gatherer's state. Stop once complete.
 */
void gatherer_state_change_handler(
        enum rawrtc_ice_gatherer_state const state, // read-only
        void* const arg // will be casted to `struct client*`
) {
printf( "%s: arg=peer_connection\n", __func__);
    struct peer_connection* client = (struct peer_connection*)arg;
    default_ice_gatherer_state_change_handler(state, arg);

    if (state == RAWRTC_ICE_GATHERER_COMPLETE) {
        printf("stop client %s\n", client->name);
        client_stop((struct peer_connection*)arg);
    }
}

static void client_get_parameters(
        struct peer_connection* const client
) {
    struct parameters* const local_parameters = &client->local_parameters;
printf("%s:%d\n", __func__, __LINE__);
    // Get local ICE parameters
    if (rawrtc_ice_gatherer_get_local_parameters(
            &local_parameters->ice_parameters, client->gatherer) != RAWRTC_CODE_SUCCESS)              {
            neat_log(client->ctx, NEAT_LOG_ERROR, "Could not get local parameters");
            exit (-1);
        }
        printf("%s:%d\n", __func__, __LINE__);

    // Get local ICE candidates
    if (rawrtc_ice_gatherer_get_local_candidates(
            &local_parameters->ice_candidates, client->gatherer) != RAWRTC_CODE_SUCCESS)              {
            neat_log(client->ctx, NEAT_LOG_ERROR, "Could not get local candidates");
            exit (-1);
        }
        printf("%s:%d\n", __func__, __LINE__);
        printf("num candidates local parameters: %zu\n", local_parameters->ice_candidates->n_candidates);

    // Get local DTLS parameters
    if (rawrtc_dtls_transport_get_local_parameters(
            &local_parameters->dtls_parameters, client->dtls_transport) != RAWRTC_CODE_SUCCESS)              {
            neat_log(client->ctx, NEAT_LOG_ERROR, "Could not get local dtls parameters");
            exit (-1);
        }
printf("%s:%d\n", __func__, __LINE__);
    // Get local SCTP parameters
    if (rawrtc_sctp_transport_get_capabilities(
            &local_parameters->sctp_parameters.capabilities) != RAWRTC_CODE_SUCCESS)              {
            neat_log(client->ctx, NEAT_LOG_ERROR, "Could not get sctp capabilities");
            exit (-1);
        }
        printf("%s:%d\n", __func__, __LINE__);
    if (rawrtc_sctp_transport_get_port(
            &local_parameters->sctp_parameters.port, client->sctp_transport) != RAWRTC_CODE_SUCCESS)              {
            neat_log(client->ctx, NEAT_LOG_ERROR, "Could not get sctp port");
            exit (-1);
        }
        printf("%s:%d\n", __func__, __LINE__);
}

static void print_local_parameters(
        struct peer_connection *client,
        char *params
) {
    struct odict* dict;
    struct odict* node;
    char *str = calloc(1, 2048);
printf("%s:%d\n", __func__, __LINE__);
    // Get local parameters
    client_get_parameters(client);
printf("%s:%d\n", __func__, __LINE__);
    // Create dict
    if (rawrtc_odict_alloc(&dict, 16) != 0) {
        printf("Error allocating dict\n");
    }
printf("%s:%d\n", __func__, __LINE__);
    // Create nodes
    if (rawrtc_odict_alloc(&node, 16) != 0) {
        printf("Error allocating node\n");
    }

    set_ice_parameters(client->local_parameters.ice_parameters, node);
    rawrtc_odict_entry_add(dict, "iceParameters", ODICT_OBJECT, node);
    rawrtc_mem_deref(node);
    rawrtc_odict_alloc(&node, 16);
    set_ice_candidates(client->local_parameters.ice_candidates, node);
    rawrtc_odict_entry_add(dict, "iceCandidates", ODICT_ARRAY, node);
    rawrtc_mem_deref(node);
    rawrtc_odict_alloc(&node, 16);
    set_dtls_parameters(client->local_parameters.dtls_parameters, node);
    rawrtc_odict_entry_add(dict, "dtlsParameters", ODICT_OBJECT, node);
    rawrtc_mem_deref(node);
    rawrtc_odict_alloc(&node, 16);
    set_sctp_parameters(client->sctp_transport, &client->local_parameters.sctp_parameters, node);
    rawrtc_odict_entry_add(dict, "sctpParameters", ODICT_OBJECT, node);
    rawrtc_mem_deref(node);

    // Print JSON
    rawrtc_dbg_info("Local Parameters:\n%H\n", rawrtc_json_encode_odict, dict);

    // Un-reference
    rawrtc_mem_deref(dict);

    sprintf(params, "{");
    set_ice_parameters_string(client->local_parameters.ice_parameters, str);
    strcat(params, str);
    set_ice_candidates_string(client->local_parameters.ice_candidates, str);
    strcat(params, ",");
    strcat(params, str);
    set_dtls_parameters_string(client->local_parameters.dtls_parameters, str);
    strcat(params, ",");
    strcat(params, str);
    set_sctp_parameters_string(client->sctp_transport, &client->local_parameters.sctp_parameters, str);
    strcat(params, ",");
    strcat(params, str);
    strcat(params, "}");
    printf("Laenge params=%lu\n", strlen(params));
    printf("Local Parameters:\n%s\n", params);
    free (str);
}

static void ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg
) {
    struct peer_connection* const client = arg;
printf("%s: arg=peer_connection\n", __func__);
    // Print local candidate
    default_ice_gatherer_local_candidate_handler(candidate, url, arg);

    // Add to other client as remote candidate (if type enabled)
    // Print local parameters (if last candidate)
    if (!candidate) {
        print_local_parameters(client, client->listening_flow->operations->userData);
        webrtc_io_parameters(client->ctx, client->listening_flow, NEAT_OK);
    }
}


static void client_init(
        struct peer_connection* const pc
) {
    struct rawrtc_certificate* certificates[1];
  //  struct rawrtc_data_channel_parameters* channel_parameters;

     // Generate certificates
    if (rawrtc_certificate_generate(&pc->certificate, NULL) != RAWRTC_CODE_SUCCESS) {
        neat_log(pc->ctx, NEAT_LOG_ERROR, "Error generating certificate");
        exit (-1);
    } else {
        neat_log(pc->ctx, NEAT_LOG_DEBUG, "Certificate generated successfully");
    }
    certificates[0] = pc->certificate;

    // Create ICE gatherer
    printf("init client %s\n", pc->name);

    if (rawrtc_ice_gatherer_create(
            &pc->gatherer, pc->gather_options,
            default_ice_gatherer_state_change_handler, default_ice_gatherer_error_handler,
            ice_gatherer_local_candidate_handler, pc) != RAWRTC_CODE_SUCCESS) {
        neat_log(pc->ctx, NEAT_LOG_ERROR, "Error creating ice gatherer");
        exit (-1);
    } else {
        neat_log(pc->ctx, NEAT_LOG_DEBUG, "Ice gatherer created successfully");
    }

    if (rawrtc_ice_transport_create(
            &pc->ice_transport, pc->gatherer,
            default_ice_transport_state_change_handler,
            default_ice_transport_candidate_pair_change_handler, pc) != RAWRTC_CODE_SUCCESS) {
        neat_log(pc->ctx, NEAT_LOG_ERROR, "Error creating ice transport");
        exit (-1);
    } else {
        neat_log(pc->ctx, NEAT_LOG_DEBUG, "Ice transport created successfully");
    }

    // Create DTLS transport
    if (rawrtc_dtls_transport_create(
            &pc->dtls_transport, pc->ice_transport, certificates, ARRAY_SIZE(certificates),
            default_dtls_transport_state_change_handler, default_dtls_transport_error_handler, pc) != RAWRTC_CODE_SUCCESS) {
        neat_log(pc->ctx, NEAT_LOG_ERROR, "Error creating dtls transport");
        exit (-1);
    } else {
        neat_log(pc->ctx, NEAT_LOG_DEBUG, "DTLS transport created successfully");
    }

    // Create SCTP transport
    if (rawrtc_sctp_transport_create(
            &pc->sctp_transport, pc->dtls_transport, pc->local_parameters.sctp_parameters.port,
            data_channel_handler, sctp_transport_state_change_handler, transport_upcall_handler, pc) != RAWRTC_CODE_SUCCESS) {
        neat_log(pc->ctx, NEAT_LOG_ERROR, "Error creating SCTP transport");
        exit (-1);
    } else {
        neat_log(pc->ctx, NEAT_LOG_DEBUG, "SCTP transport created successfully");
    }

    // Get SCTP capabilities
 /*   if (rawrtc_sctp_transport_get_capabilities(&local->sctp_capabilities) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error getting SCTP capabilities");
        exit (-1);
    } else {
        neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Got SCTP capabilities successfully");
    }*/

        // Get data transport
    if (rawrtc_sctp_transport_get_data_transport(
            &pc->data_transport, pc->sctp_transport) != RAWRTC_CODE_SUCCESS) {
        neat_log(pc->ctx, NEAT_LOG_ERROR, "Error getting SCTP data transport");
        exit (-1);
    } else {
        neat_log(pc->ctx, NEAT_LOG_DEBUG, "Got SCTP data transport successfully");
    }

}

static void client_start_gathering(
        struct peer_connection* const pc
) {
printf("%s\n", __func__);
    // Start gathering
    if (rawrtc_ice_gatherer_gather(pc->gatherer, NULL) != RAWRTC_CODE_SUCCESS) {
        neat_log(pc->ctx, NEAT_LOG_ERROR, "Error gathering candidates");
        exit (-1);
    } else {
        neat_log(pc->ctx, NEAT_LOG_DEBUG, "Ice candidates gathered successfully");
    }
}

neat_error_code
neat_webrtc_write_to_channel(struct neat_ctx *ctx,
            struct neat_flow *flow,
            const unsigned char *buffer,
            uint32_t amt,
            struct neat_tlv optional[],
            unsigned int opt_count)
{
    neat_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);
    struct mbuf *buf = rawrtc_mbuf_alloc(amt);
    int found = 0;
    printf("amt=%d\n", amt);
    if(rawrtc_mbuf_write_mem(buf, (const uint8_t *)buffer, (size_t)amt) != 0) {
        printf("Fehler beim Schreiben von mbuf\n");
    }
    rawrtc_mbuf_set_pos(buf, 0);
    struct peer_connection *pc = flow->peer_connection;
    printf("pc=%p\n", (void *)pc);
    struct rawrtc_sctp_transport *sctp = pc->sctp_transport;
    printf("sctp_transport=%p\n", (void *)sctp);
    printf("num channels: %d\n", sctp->n_channels);
    int i = 0;
    for (i = 0; i < (int)pc->max_flows; i++) {
        if (pc->flows[i]->state == NEAT_FLOW_OPEN && pc->flows[i]->flow == flow) {
            printf("send %zu bytes on %s \n", buf->end, pc->flows[i]->label);
            rawrtc_data_channel_send(pc->flows[i]->channel, buf, true);
            found = 1;
            break;
        }
    }
    if (found) {
        printf("data was sent on %s\n", pc->flows[i]->label);
    } else {
        printf("no open channel found\n");
    }
    return NEAT_OK;
}


// TODO: return the candidate
void
neat_webrtc_gather_candidates(neat_ctx *ctx, neat_flow *flow, uint16_t peer_role, const char *label) {
    struct rawrtc_ice_gather_options* gather_options;
    char** ice_candidate_types = NULL;
    size_t n_ice_candidate_types = 0;
    enum rawrtc_ice_role role;
    char* const stun_google_com_urls[] = {"stun:stun.l.google.com:19302",
                                          "stun:stun1.l.google.com:19302"};
printf("flow=%p, flow->name=%s\n", (void *)flow, flow->name);

    if (peer.max_flows == 0) {
	    peer.ice_candidate_types = ice_candidate_types;
	    peer.n_ice_candidate_types = n_ice_candidate_types;

        struct rawrtc_flow* r_flow = calloc(1, sizeof(struct rawrtc_flow));
        r_flow->flow = flow;
        r_flow->state = NEAT_FLOW_WAITING;
        r_flow->label = strdup(label);
        peer.flows = calloc(1, 100 * sizeof(void *));
        peer.flows[peer.max_flows] = r_flow;
        peer.n_flows++;
        peer.max_flows++;
       // peer.active_flow = flow;
        peer.ctx = flow->ctx;
        peer.remote_host = strdup(flow->name);

        neat_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

        if (peer_role == 0) {
            role = RAWRTC_ICE_ROLE_CONTROLLING;
            peer.name = "A";
        } else {
            role = RAWRTC_ICE_ROLE_CONTROLLED;
            peer.name = "B";
        }

        if (rawrtc_init() != RAWRTC_CODE_SUCCESS) {
            neat_log(ctx, NEAT_LOG_ERROR, "Error initializing RawRTC");
            exit (-1);
        }

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

        peer.ice_candidate_types = ice_candidate_types;
        peer.n_ice_candidate_types = n_ice_candidate_types;
        peer.gather_options = gather_options;
        peer.role = role;
        rawrtc_list_init(&peer.data_channels);

        printf("Now init client \n");
	    // Initialise client
        client_init(&peer);


        // Start client
        client_start_gathering(&peer);

        rawrtc_fd_listen(STDIN_FILENO, 1, parse_remote_parameters, &peer);
    } else {
        printf("num flows = %zu\n", peer.n_flows);
        printf("peer.remote_host: %s, flow->name: %s\n", peer.remote_host, flow->name);
        // same peer_connection
        if (peer.n_flows > 0 && !strcmp(peer.remote_host, flow->name)) {
        printf("%d\n", __LINE__);
            struct rawrtc_flow* r_flow = calloc(1, sizeof(struct rawrtc_flow));
            r_flow->label = strdup(label);
printf("%d\n", __LINE__);
            if (peer.sctp_transport->state == RAWRTC_SCTP_TRANSPORT_STATE_CONNECTED) {
                struct rawrtc_data_channel_parameters* channel_parameters;
                struct data_channel_helper* data_channel_negotiated;
printf("%d\n", __LINE__);
                r_flow->state = NEAT_FLOW_OPEN;
                // Create data channel helper
                data_channel_helper_create(
                    &data_channel_negotiated, &peer, (char *)label);
printf("%d\n", __LINE__);
                // Create data channel parameters
                if (rawrtc_data_channel_parameters_create(
                    &channel_parameters, data_channel_negotiated->label,
                    RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_UNORDERED, 0, NULL, false, 0)  != RAWRTC_CODE_SUCCESS)              {
                    neat_log(peer.ctx, NEAT_LOG_ERROR, "Could not create channel parameters parameters");
                    exit (-1);
                }
                printf("call rawrtc_data_channel_create\n");
                if (rawrtc_data_channel_create(
                    &data_channel_negotiated->channel, peer.data_transport,
                    channel_parameters, NULL,
                    default_data_channel_open_handler,    default_data_channel_buffered_amount_low_handler,
                    default_data_channel_error_handler, data_channel_close_handler,
                    data_channel_message_handler, data_channel_negotiated) != RAWRTC_CODE_SUCCESS) {
                    neat_log(peer.ctx, NEAT_LOG_ERROR, "Error creating data channel");
                    exit (-1);
                } else {
                    neat_log(peer.ctx, NEAT_LOG_DEBUG, "Created data channel successfully");
                }
                r_flow->channel = data_channel_negotiated->channel;
               // peer.active_flow = flow;

            } else {
                r_flow->state = NEAT_FLOW_WAITING;
            }
            flow->peer_connection = &peer;
            r_flow->flow = flow;
            peer.flows[peer.max_flows] = r_flow;
            peer.n_flows++;
            peer.max_flows++;
        }
    }
}

int
rawrtc_stop_client(struct peer_connection *pc) {
    client_stop(pc);
    printf("nach client_stop\n");
    free(pc->flows);
    printf("nach free flows\n");
    rawrtc_close();
    return NEAT_OK;
}

int
rawrtc_close_flow(neat_flow *flow, struct peer_connection *pc)
{
printf("%s\n", __func__);
    for (int i = 0; i < (int)pc->max_flows; i++) {
        if (pc->flows[i]->flow == flow) {
            if (rawrtc_data_channel_close(pc->flows[i]->channel) != RAWRTC_CODE_SUCCESS) {
                printf("%s could not be closed \n", pc->flows[i]->label);
                return NEAT_ERROR_INTERNAL;
            } else {
                return NEAT_OK;
            }
        }
    }
    return NEAT_ERROR_INTERNAL;
}

void
neat_set_listening_flow(neat_ctx *ctx, neat_flow *flow)
{
    flow->state = NEAT_FLOW_OPEN;
    peer.listening_flow = flow;
    peer.ctx = ctx;
}

neat_error_code neat_send_remote_parameters(struct neat_ctx *ctx, struct neat_flow *flow, char* params)
{
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
    printf("Remote Parameter: %s\n", params);
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
    parse_param_from_signaling_server(ctx, flow, params);
    free(params);
    return NEAT_OK;
}

#endif
