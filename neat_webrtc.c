#include <stdio.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_webrtc_tools.h"
#include <rawrtc.h>

#define ARRAY_SIZE(a) ((sizeof(a))/(sizeof((a)[0])))

struct rawrtc_ice_gatherer* gatherer;

static neat_flow *n_flow = NULL;

//static uv_timer_t *timer_handle = NULL;

static void data_channel_open_handler(
        void* const arg
);

struct data_channel_sctp_client {
    char* name;
    char** ice_candidate_types;
    size_t n_ice_candidate_types;
    struct rawrtc_ice_gather_options* gather_options;
    struct rawrtc_ice_parameters* ice_parameters;
    struct rawrtc_dtls_parameters* dtls_parameters;
    struct rawrtc_sctp_capabilities* sctp_capabilities;
    enum rawrtc_ice_role role;
    struct rawrtc_certificate* certificate;
    uint16_t sctp_port;
    struct rawrtc_ice_gatherer* gatherer;
    struct rawrtc_ice_transport* ice_transport;
    struct rawrtc_dtls_transport* dtls_transport;
    struct rawrtc_sctp_transport* sctp_transport;
    struct rawrtc_data_transport* data_transport;
    struct data_channel_helper* data_channel_negotiated;
    struct data_channel_helper* data_channel;
    struct data_channel_sctp_client* other_client;
};

    struct data_channel_sctp_client peer;

static void client_stop(
        struct data_channel_sctp_client* const client
) {
        // Stop transports & close gatherer
    if (client->data_channel) {
        if (rawrtc_data_channel_close(client->data_channel->channel) != RAWRTC_CODE_SUCCESS) {
        printf("Error closing data channel \n");
        exit (-1);
    }
    }
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
    client->data_channel = rawrtc_mem_deref(client->data_channel);
    client->data_channel_negotiated = rawrtc_mem_deref(client->data_channel_negotiated);
    client->sctp_capabilities = rawrtc_mem_deref(client->sctp_capabilities);
    client->dtls_parameters = rawrtc_mem_deref(client->dtls_parameters);
    client->ice_parameters = rawrtc_mem_deref(client->ice_parameters);
    client->data_transport = rawrtc_mem_deref(client->data_transport);
    client->sctp_transport = rawrtc_mem_deref(client->sctp_transport);
    client->dtls_transport = rawrtc_mem_deref(client->dtls_transport);
    client->ice_transport = rawrtc_mem_deref(client->ice_transport);
    client->gatherer = rawrtc_mem_deref(client->gatherer);
    client->certificate = rawrtc_mem_deref(client->certificate);
}

static void dtls_transport_state_change_handler(
        enum rawrtc_dtls_transport_state const state, // read-only
        void* const arg
) {
    struct data_channel_sctp_client* const client = arg;

    // Print state
    default_dtls_transport_state_change_handler(state, arg);

    // Open? Send message (twice to test the buffering)
    if (state == RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED) {
        enum rawrtc_dtls_role role;

        // Renew DTLS parameters
        rawrtc_mem_deref(client->dtls_parameters);
        if (rawrtc_dtls_transport_get_local_parameters(
                &client->dtls_parameters, client->dtls_transport) != RAWRTC_CODE_SUCCESS)              {
            neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error getting local dtls parameters");
            exit (-1);
        } else {
            neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Got local dtls parameters successfully");
        }

        // Get DTLS role
        if (rawrtc_dtls_parameters_get_role(&role, client->dtls_parameters) != RAWRTC_CODE_SUCCESS)              {
            neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Could not get role");
            exit (-1);
        } else {
            neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Got role successfully");
        }
        printf("(%s) DTLS role: %s\n", client->name, rawrtc_dtls_role_to_str(role));

        // Client? Create data channel
        if (role == RAWRTC_DTLS_ROLE_CLIENT) {
            struct rawrtc_data_channel_parameters* channel_parameters;

            // Create data channel helper
            data_channel_helper_create(
                    &client->data_channel, (struct client *) client, "bear-noises");

            // Create data channel parameters
            if (rawrtc_data_channel_parameters_create(
                    &channel_parameters, client->data_channel->label,
                    RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_UNORDERED, 0, NULL, false, 0) != RAWRTC_CODE_SUCCESS)              {
            neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Could not create data channel parameters");
            exit (-1);
        } else {
            neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Data channel parameters created successfully");
        }

            // Create data channel
            if (rawrtc_data_channel_create(
                    &client->data_channel->channel, client->data_transport,
                    channel_parameters, NULL,
                    data_channel_open_handler,
                    default_data_channel_buffered_amount_low_handler,
                    default_data_channel_error_handler, default_data_channel_close_handler,
                    default_data_channel_message_handler, client->data_channel) != RAWRTC_CODE_SUCCESS)              {
            neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Could not create data channel");
            exit (-1);
        } else {
            neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Data channel created successfully");
        }

            // Un-reference
            rawrtc_mem_deref(channel_parameters);
        }
    }
}
#if 0
static void timer_handler(uv_timer_t *handle)
{
    struct data_channel_helper* const channel = handle->data;
    struct data_channel_sctp_client* const client =
            (struct data_channel_sctp_client*) channel->client;
    struct mbuf* buffer;
    enum rawrtc_code error;
    enum rawrtc_dtls_role role;


    // Compose message (16 MiB)
    buffer = rawrtc_mbuf_alloc(1 << 24);
        if (!buffer) {
    printf("no memory\n");
    	exit (1);
    }
    if (rawrtc_mbuf_fill(buffer, 'M', rawrtc_mbuf_get_space(buffer))  != RAWRTC_CODE_SUCCESS) {
            printf("Error filling buffer\n");
            exit (-1);
        }
    rawrtc_mbuf_set_pos(buffer, 0);

    // Send message
    printf("(%s) Sending %zu bytes\n", client->name, rawrtc_mbuf_get_left(buffer));
    error = rawrtc_data_channel_send(channel->channel, buffer, true);
    if (error) {
        printf("Could not send, reason: %s\n", rawrtc_code_to_str(error));
    }
    rawrtc_mem_deref(buffer);

    // Get DTLS role
    if (rawrtc_dtls_parameters_get_role(&role, client->dtls_parameters) != RAWRTC_CODE_SUCCESS)              {
            neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Could not get role");
            exit (-1);
        } else {
            neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Got role successfully");
        }
    if (role == RAWRTC_DTLS_ROLE_CLIENT) {
        // Close bear-noises
        printf("(%s) Closing channel %s\n", client->name, channel->label);
        if (rawrtc_data_channel_close(client->data_channel->channel) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error closing channel");
            exit (-1);
        }
    }
}
#endif

static void data_channel_open_handler(
        void* const arg
) {
    struct data_channel_helper* const channel = arg;
    struct data_channel_sctp_client* const client =
            (struct data_channel_sctp_client*) channel->client;
    struct mbuf* buffer;
    enum rawrtc_code error;

    // Print open event
    default_data_channel_open_handler(arg);

    // Send data delayed on bear-noises
    if (strcmp(channel->label, "bear-noises") == 0) {
        timer_handle->data = arg;
        if (uv_timer_start(timer_handle, timer_handler, 1000, 0) < 0) {
			printf("error starting timer\n");
			return;
		}
       // tmr_start(&timer, 1000, timer_handler, channel);
        return;
    }

    // Compose message (256 KiB)
    buffer = rawrtc_mbuf_alloc(1 << 18);
    if (!buffer) {
    printf("no memory\n");
    	exit (1);
    }

    if (rawrtc_mbuf_fill(buffer, 'M', rawrtc_mbuf_get_space(buffer))  != RAWRTC_CODE_SUCCESS) {
            printf("Error filling buffer\n");
            exit (-1);
        }
    rawrtc_mbuf_set_pos(buffer, 0);

    // Send message
    printf("(%s) Sending %zu bytes\n", client->name, rawrtc_mbuf_get_left(buffer));
    error = rawrtc_data_channel_send(channel->channel, buffer, true);
    if (error) {
        printf("Could not send, reason: %s\n", rawrtc_code_to_str(error));
    }
    rawrtc_mem_deref(buffer);
}

static void sctp_transport_state_change_handler(
    enum rawrtc_sctp_transport_state const state,
    void* const arg
) {
    struct data_channel_sctp_client* const client = arg;

    // Print state
    default_sctp_transport_state_change_handler(state, arg);

    // Open? Send message (twice to test the buffering)
    if (state == RAWRTC_SCTP_TRANSPORT_STATE_CONNECTED ||
            state == RAWRTC_SCTP_TRANSPORT_STATE_CONNECTING) {
        struct sctp_sendv_spa spa;
        enum rawrtc_code error;

        // Compose meowing message
        struct mbuf* buffer = rawrtc_mbuf_alloc(1024);
        rawrtc_mbuf_printf(buffer, "Hello! Meow meow meow meow meow meow meow meow meow!");
        rawrtc_mbuf_set_pos(buffer, 0);

        // Set SCTP stream, protocol identifier and flags
        spa.sendv_sndinfo.snd_sid = 0;
        spa.sendv_sndinfo.snd_flags = SCTP_EOR;
        spa.sendv_sndinfo.snd_ppid = htonl(RAWRTC_SCTP_TRANSPORT_PPID_DCEP);
        spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;

        // Send message
        printf("Sending %zu bytes: %s\n", rawrtc_mbuf_get_left(buffer), rawrtc_mbuf_buf(buffer));
                   //  mbuf_get_left(buffer));
        error = rawrtc_sctp_transport_send(
                client->sctp_transport, buffer, &spa, sizeof(spa), SCTP_SENDV_SPA, 0);
        if (error) {
            printf("Could not send, reason: %s\n", rawrtc_code_to_str(error));
        }
        rawrtc_mem_deref(buffer);
    }
}


/*
 * Print the ICE gatherer's state. Stop once complete.
 */
void gatherer_state_change_handler(
        enum rawrtc_ice_gatherer_state const state, // read-only
        void* const arg // will be casted to `struct client*`
) {
printf( "%s\n", __func__);
    struct data_channel_sctp_client* client = (struct data_channel_sctp_client*)arg;
    default_ice_gatherer_state_change_handler(state, arg);

    if (state == RAWRTC_ICE_GATHERER_COMPLETE) {
        printf("stop client %s\n", client->name);
        client_stop((struct data_channel_sctp_client*)arg);
    }

  /*  if (state == RAWRTC_ICE_GATHERER_COMPLETE) {
        printf("close gatherer\n");
        if (rawrtc_ice_gatherer_close(gatherer) != RAWRTC_CODE_SUCCESS) {
            printf("Error closing gatherer\n");
            exit (-1);
        }
    }*/
  /*  if (state == RAWRTC_ICE_GATHERER_CLOSED) {
        printf("Gatherer closed successfully\n");
        rawrtc_mem_deref(gatherer->options);
        rawrtc_mem_deref (gatherer);
        printf("close rawrtc\n");
        rawrtc_close();
        printf("rawrtc_closed\n");
        neat_close(n_flow->ctx, n_flow);
    }*/
}

static void ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg
) {
    struct data_channel_sctp_client* const client = arg;
printf("%s\n", __func__);
    // Print local candidate
    default_ice_gatherer_local_candidate_handler(candidate, url, arg);

    // Add to other client as remote candidate (if type enabled)
    add_to_other_if_ice_candidate_type_enabled(
            arg, candidate, client->other_client->ice_transport);
}


static void client_init(
        struct data_channel_sctp_client* const local
) {
    struct rawrtc_certificate* certificates[1];
    struct rawrtc_data_channel_parameters* channel_parameters;
printf("generate certificate\n");
     // Generate certificates
    if (rawrtc_certificate_generate(&local->certificate, NULL) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error generating certificate");
        exit (-1);
    } else {
        neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Certificate generated successfully");
    }
    certificates[0] = local->certificate;

    // Create ICE gatherer
    printf("init client %s\n", local->name);
    printf("local->other_client=%p , local->other_client->ice_transport=%p\n", (void *) local->other_client, (void *)local->other_client->ice_transport);
    if (rawrtc_ice_gatherer_create(
            &local->gatherer, local->gather_options,
            default_ice_gatherer_state_change_handler, default_ice_gatherer_error_handler,
            ice_gatherer_local_candidate_handler, local) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error creating ice gatherer");
        exit (-1);
    } else {
        neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Ice gatherer created successfully");
    }

    if (rawrtc_ice_transport_create(
            &local->ice_transport, local->gatherer,
            default_ice_transport_state_change_handler,
            default_ice_transport_candidate_pair_change_handler, local) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error creating ice transport");
        exit (-1);
    } else {
        neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Ice transport created successfully");
    }
printf("ice_transport=%p\n", (void *)local->ice_transport);
    // Create DTLS transport
    if (rawrtc_dtls_transport_create(
            &local->dtls_transport, local->ice_transport, certificates, ARRAY_SIZE(certificates),
            dtls_transport_state_change_handler, default_dtls_transport_error_handler, local) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error creating dtls transport");
        exit (-1);
    } else {
        neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "DTLS transport created successfully");
    }

    // Create SCTP transport
    if (rawrtc_sctp_transport_create(
            &local->sctp_transport, local->dtls_transport, local->sctp_port,
            default_data_channel_handler, default_sctp_transport_state_change_handler, local) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error creating SCTP transport");
        exit (-1);
    } else {
        neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "SCTP transport created successfully");
    }

    // Get SCTP capabilities
    if (rawrtc_sctp_transport_get_capabilities(&local->sctp_capabilities) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error getting SCTP capabilities");
        exit (-1);
    } else {
        neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Got SCTP capabilities successfully");
    }

        // Get data transport
    if (rawrtc_sctp_transport_get_data_transport(
            &local->data_transport, local->sctp_transport) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error getting SCTP data transport");
        exit (-1);
    } else {
        neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Got SCTP data transport successfully");
    }

    // Create data channel helper
    data_channel_helper_create(
            &local->data_channel_negotiated, (struct client *) local, "cat-noises");

    // Create data channel parameters
    if (rawrtc_data_channel_parameters_create(
            &channel_parameters, local->data_channel_negotiated->label,
            RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_ORDERED, 0, NULL, true, 0) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error creating data channel parameters");
        exit (-1);
    } else {
        neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Created data channel parameters successfully");
    }

    // Create pre-negotiated data channel
    if (rawrtc_data_channel_create(
            &local->data_channel_negotiated->channel, local->data_transport,
            channel_parameters, NULL,
            data_channel_open_handler, default_data_channel_buffered_amount_low_handler,
            default_data_channel_error_handler, default_data_channel_close_handler,
            default_data_channel_message_handler, local->data_channel_negotiated) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error creating data channel");
        exit (-1);
    } else {
        neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Created data channel successfully");
    }

    // Un-reference
    rawrtc_mem_deref(channel_parameters);
}

static void client_start(
        struct data_channel_sctp_client* const local,
        struct data_channel_sctp_client* const remote
) {
printf("start client %s\n", local->name);
    // Get & set ICE parameters
    if (rawrtc_ice_gatherer_get_local_parameters(
            &local->ice_parameters, remote->gatherer) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error getting local parameters");
        exit (-1);
    } else {
        neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Getting local parameters was successful");
    }

    // Start gathering
    if (rawrtc_ice_gatherer_gather(local->gatherer, NULL) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error gathering candidates");
        exit (-1);
    } else {
        neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Ice candidates gathered successfully");
    }

    // Start ICE transport
    if (rawrtc_ice_transport_start(
            local->ice_transport, local->gatherer, local->ice_parameters, local->role) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error starting ice transport");
        exit (-1);
    } else {
        neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Ice transport started successfully");
    }

    // Get & set DTLS parameters
    if (rawrtc_dtls_transport_get_local_parameters(
            &remote->dtls_parameters, remote->dtls_transport) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error getting dtls parameters");
        exit (-1);
    } else {
        neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Dtls transport parameters got successfully");
    }

    // Start DTLS transport
    if (rawrtc_dtls_transport_start(
            local->dtls_transport, remote->dtls_parameters) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error starting dtls transport");
        exit (-1);
    } else {
        neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "Dtls transport started successfully");
    }

    // Start SCTP transport
    if (rawrtc_sctp_transport_start(
            local->sctp_transport, remote->sctp_capabilities, remote->sctp_port) != RAWRTC_CODE_SUCCESS) {
        neat_log(n_flow->ctx, NEAT_LOG_ERROR, "Error starting SCTP transport");
        exit (-1);
    } else {
        neat_log(n_flow->ctx, NEAT_LOG_DEBUG, "SCTP transport started successfully");
    }

}

// TODO: return the candidate
void
neat_webrtc_gather_candidates(neat_ctx *ctx, neat_flow *flow) {
    struct rawrtc_ice_gather_options* gather_options;
    char** ice_candidate_types = NULL;
    size_t n_ice_candidate_types = 0;
    enum rawrtc_ice_role role;
    char* const stun_google_com_urls[] = {"stun:stun.l.google.com:19302",
                                          "stun:stun1.l.google.com:19302"};

	peer.ice_candidate_types = ice_candidate_types;
	peer.n_ice_candidate_types = n_ice_candidate_types;


    n_flow = flow;
    n_flow->ctx = flow->ctx;

    neat_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (rawrtc_init() != RAWRTC_CODE_SUCCESS) {
        neat_log(ctx, NEAT_LOG_ERROR, "Error initializing RawRTC");
        exit (-1);
    }

    rawrtc_dbg_init(DBG_DEBUG, DBG_ALL);

    printf("ctx=%p loop=%p\n", (void *)ctx, (void *)ctx->loop);
    rawrtc_set_uv_loop((void *)(ctx->loop));

    rawrtc_alloc_fds(128);

        // Get ICE role
    get_ice_role(&role, argv[1]);

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
    peer.name = "A";
    peer.ice_candidate_types = ice_candidate_types;
    peer.n_ice_candidate_types = n_ice_candidate_types;
    peer.gather_options = gather_options;
    peer.role = role;

  /*  timer_handle = calloc(1, sizeof(uv_timer_t));
	if (uv_timer_init(ctx->loop, timer_handle) < 0) {
		printf("error initializing timer\n");
	}*/

printf("Now init client \n");
	// Initialise client
    client_init(&peer);


    // Start client
    client_start_gathering(&peer);

    rawrtc_fd_listen(STDIN_FILENO, FD_READ, parse_remote_parameters, &peer);
}



