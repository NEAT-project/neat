#include <stdio.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_webrtc_tools.h"
#include <rawrtc.h>

#define STDIN_FILENO 0

#define ARRAY_SIZE(a) ((sizeof(a))/(sizeof((a)[0])))

struct rawrtc_ice_gatherer* gatherer;

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
        webrtc_io_writable(client->ctx, client->flow, NEAT_OK);
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
    printf("client->remote_parameters.ice_candidates->n_candidates=%zu\n", client->remote_parameters.ice_candidates->n_candidates);
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
       // uv_timer_stop(timer_handle);

        printf("close rawrtc\n");
        rawrtc_close();
        printf("rawrtc_closed\n");
        neat_close(client->ctx, client->flow);
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


static void client_stop(
        struct peer_connection* const client
) {
printf("%s\n", __func__);
        // Stop transports & close gatherer
    // Clear data channels
    rawrtc_list_flush(&client->data_channels);

    if (rawrtc_sctp_transport_stop(client->sctp_transport) != RAWRTC_CODE_SUCCESS) {
        printf("Error stopping sctp transport \n");
        exit (-1);
    }
    if (rawrtc_dtls_transport_stop(client->dtls_transport) != RAWRTC_CODE_SUCCESS) {
        printf("Error stopping dtls transport \n");
        exit (-1);
    }
    if (rawrtc_ice_transport_stop(client->ice_transport) != RAWRTC_CODE_SUCCESS) {
        printf("Error stopping ice transport \n");
        exit (-1);
    }
    if (rawrtc_ice_gatherer_close(client->gatherer) != RAWRTC_CODE_SUCCESS) {
        printf("Error closing gatherer\n");
        exit (-1);
    }

    // Un-reference & close
    parameters_destroy(&client->remote_parameters);
    parameters_destroy(&client->local_parameters);
    client->data_transport = rawrtc_mem_deref(client->data_transport);
    client->sctp_transport = rawrtc_mem_deref(client->sctp_transport);
    client->dtls_transport = rawrtc_mem_deref(client->dtls_transport);
    client->ice_transport = rawrtc_mem_deref(client->ice_transport);
    client->gatherer = rawrtc_mem_deref(client->gatherer);
    client->certificate = rawrtc_mem_deref(client->certificate);
    client->gather_options = rawrtc_mem_deref(client->gather_options);
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
   webrtc_io_readable(client->ctx, client->flow, NEAT_OK, (void *)buffer->buf, buffer->end);
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
    if (rawrtc_data_channel_set_close_handler(channel, default_data_channel_close_handler)!= RAWRTC_CODE_SUCCESS) {
            neat_log(client->ctx, NEAT_LOG_ERROR, "Could not set close handler");
            exit (-1);
        }
    if (rawrtc_data_channel_set_message_handler(channel, data_channel_message_handler)!= RAWRTC_CODE_SUCCESS) {
            neat_log(client->ctx, NEAT_LOG_ERROR, "Could not set message handler");
            exit (-1);
        }
        client->flow->peer_connection = client;
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
        client->flow->state = NEAT_FLOW_OPEN;

        if (client->flow->operations && client->flow->operations->on_connected) {
            client->flow->peer_connection = client;
            webrtc_io_connected(client->ctx, client->flow, NEAT_OK);
        }

        struct rawrtc_data_channel_parameters* channel_parameters;
        struct data_channel_helper* data_channel_negotiated;

        // Create data channel helper
        data_channel_helper_create(
            &data_channel_negotiated, (struct peer_connection *) arg, "first");

        // Create data channel parameters
        if (rawrtc_data_channel_parameters_create(
                    &channel_parameters, data_channel_negotiated->label,
                    RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_UNORDERED, 0, NULL, false, 0)  != RAWRTC_CODE_SUCCESS)              {
            neat_log(client->ctx, NEAT_LOG_ERROR, "Could not create channel parameters parameters");
            exit (-1);
        }
        printf("call rawrtc_data_channel_create\n");
        if (rawrtc_data_channel_create(
            &data_channel_negotiated->channel, client->data_transport,
            channel_parameters, NULL,
            default_data_channel_open_handler, default_data_channel_buffered_amount_low_handler,
            default_data_channel_error_handler, default_data_channel_close_handler,
            default_data_channel_message_handler, data_channel_negotiated) != RAWRTC_CODE_SUCCESS) {
            neat_log(client->ctx, NEAT_LOG_ERROR, "Error creating data channel");
            exit (-1);
        } else {
            neat_log(client->ctx, NEAT_LOG_DEBUG, "Created data channel successfully");
        }

        if (rawrtc_dtls_parameters_get_role(&role, client->local_parameters.dtls_parameters) != RAWRTC_CODE_SUCCESS) {
            neat_log(client->ctx, NEAT_LOG_ERROR, "Could not get role");
            exit (-1);
        }
        client->flow->peer_connection = client;

        // Un-reference
        rawrtc_mem_deref(channel_parameters);
    }
    if (state == RAWRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        neat_notify_close(client->flow);
    }
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
        struct peer_connection *client
) {
    struct odict* dict;
    struct odict* node;
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
        print_local_parameters(client);
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
    for (i = 0; i < sctp->n_channels; i++) {
        if (sctp->channels[i] && sctp->channels[i]->state == RAWRTC_DATA_CHANNEL_STATE_OPEN) {
        printf("send %zu bytes on channel %d \n", buf->end, i);
            rawrtc_data_channel_send(sctp->channels[i], buf, true);
            found = 1;
            break;
        }
    }
    if (found) {
        printf("data was sent on channel sid %d\n", i);
    } else {
        printf("no open channel found\n");
    }
    return NEAT_OK;
}


// TODO: return the candidate
void
neat_webrtc_gather_candidates(neat_ctx *ctx, neat_flow *flow, uint16_t peer_role) {
    struct rawrtc_ice_gather_options* gather_options;
    char** ice_candidate_types = NULL;
    size_t n_ice_candidate_types = 0;
    enum rawrtc_ice_role role;
    char* const stun_google_com_urls[] = {"stun:stun.l.google.com:19302",
                                          "stun:stun1.l.google.com:19302"};

	peer.ice_candidate_types = ice_candidate_types;
	peer.n_ice_candidate_types = n_ice_candidate_types;


    peer.flow = flow;
    peer.ctx = flow->ctx;

    neat_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (peer_role == 0) {
        role = RAWRTC_ICE_ROLE_CONTROLLING;
    } else {
        role = RAWRTC_ICE_ROLE_CONTROLLED;
    }

    if (rawrtc_init() != RAWRTC_CODE_SUCCESS) {
        neat_log(ctx, NEAT_LOG_ERROR, "Error initializing RawRTC");
        exit (-1);
    }

    rawrtc_dbg_init(DBG_DEBUG, DBG_ALL);

    printf("ctx=%p loop=%p\n", (void *)ctx, (void *)ctx->loop);
    rawrtc_set_uv_loop((void *)(ctx->loop));

    rawrtc_alloc_fds(128);

        // Get ICE role
   // get_ice_role(&role, flow->role);

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

      // Setup client A
    if (peer_role == 0)
        peer.name = "A";
    else
        peer.name = "B";
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
}

void
rawrtc_stop_client(struct peer_connection *pc) {
    client_stop(pc);
}



