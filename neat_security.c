#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_security.h"

#ifdef NEAT_USETLS
typedef unsigned int bool;
#define true 1
#define false 0


static void
neat_security_filter_dtor(struct neat_iofilter *filter)
{
    struct security_data *private;
    private = (struct security_data *) filter->userData;

    // private->outputBIO and private->inputBIO are freed by SSL_free(private->ssl)
    if (private && private->ssl) {
        SSL_free(private->ssl);
        private->ssl = NULL;
    }

    if (private && private->ctx) {
        SSL_CTX_free(private->ctx);
        private->ctx = NULL;
    }
    free(private);
    filter->userData = NULL;
}

static neat_error_code
drain_output(struct neat_ctx *ctx, struct neat_flow *flow,
             struct neat_iofilter *filter, struct neat_tlv optional[], unsigned int opt_count)
{
    neat_error_code rv;
    struct security_data *private;
    private = (struct security_data *) filter->userData;
    int didFilterWrite = 0;

    if (!private->outCipherBufferUsed) {
        return NEAT_OK;
    }

    for (filter = filter->next; filter; filter = filter->next) {
        // find the next filter and call it
        if (!filter->writefx) {
            continue;
        }
        rv = filter->writefx(ctx, flow, filter,
                             private->outCipherBuffer,
                             private->outCipherBufferUsed, optional, opt_count);
        if (rv != NEAT_OK) {
            return rv;
        }
        didFilterWrite = 1;
        break;
    }
    if (!didFilterWrite) {
        rv = flow->writefx(ctx, flow,
                           private->outCipherBuffer,
                           private->outCipherBufferUsed, optional, opt_count);
        if (rv != NEAT_OK) {
            return rv;
        }
    }
    neat_log(ctx, NEAT_LOG_DEBUG, "wrote out %d cipher text to transport",
             private->outCipherBufferUsed);

    // wrote it all.
    private->outCipherBufferUsed = 0;
    return NEAT_OK;
}

// gathers from network into inCipherBuffer
static neat_error_code
gather_input(struct neat_ctx *ctx, struct neat_flow *flow,
             struct neat_iofilter *filter, struct neat_tlv optional[], unsigned int opt_count)
{
    neat_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);
    struct security_data *private = (struct security_data *) filter->userData;
    uint32_t actualAmt;
    uint32_t avail = CIPHER_BUFFER_SIZE - private->inCipherBufferUsed;
    if (!avail) {
        return NEAT_ERROR_WOULD_BLOCK;
    }
    neat_error_code rv = flow->readfx(ctx, flow, private->inCipherBuffer + private->inCipherBufferUsed,
                                      avail, &actualAmt, optional, opt_count);
    neat_log(ctx, NEAT_LOG_DEBUG, "read in %d cipher text from transport (%u)",
             (rv == NEAT_OK) ? actualAmt : 0, rv);
    if (rv == NEAT_OK && actualAmt) {
        private->inCipherBufferUsed += actualAmt;
    } else if (rv == NEAT_OK && !actualAmt) {
        rv = NEAT_ERROR_IO;
    }

    return rv;
    // todo filters!
}
static neat_error_code
neat_security_filter_write(struct neat_ctx *ctx, struct neat_flow *flow,
                           struct neat_iofilter *filter,
                           const unsigned char *buffer, uint32_t amt,
                           struct neat_tlv optional[], unsigned int opt_count);
static neat_error_code
neat_security_filter_read(struct neat_ctx *ctx, struct neat_flow *flow,
                          struct neat_iofilter *filter,
                          unsigned char *buffer, uint32_t amt,
                          uint32_t *actualAmt,
                          struct neat_tlv optional[], unsigned int opt_count);

static neat_error_code
neat_dtls_write(struct neat_ctx *ctx, struct neat_flow *flow,
                           const unsigned char *buffer, uint32_t amt,
                           struct neat_tlv optional[],
                           unsigned int opt_count);
static neat_error_code
neat_dtls_read(struct neat_ctx *ctx, struct neat_flow *flow,
                          unsigned char *buffer, uint32_t amt,
                          uint32_t *actualAmt,
                          struct neat_tlv optional[], unsigned int opt_count);
static neat_error_code
neat_dtls_handshake(struct neat_flow_operations *opCB);


static neat_error_code
neat_security_handshake(struct neat_flow_operations *opCB)
{
    // neat_log(opCB->ctx, NEAT_LOG_DEBUG, "%s", __func__);
    neat_error_code rv = neat_write(opCB->ctx, opCB->flow, NULL, 0, NULL, 0);
    if (rv == NEAT_ERROR_WOULD_BLOCK) {
        return rv;
    }
    // neat_log(NEAT_LOG_DEBUG, "%s handshake not blocking", __func__);
    for (struct neat_iofilter *filter = opCB->flow->iofilters;
         filter; filter = filter->next) {
        if (filter->writefx == neat_security_filter_write ||
            filter->readfx == neat_security_filter_read) {
            struct security_data *private = (struct security_data *) filter->userData;
            // pop application functions back onto stack
            opCB->on_writable = private->pushed_on_writable;
            opCB->on_readable =  private->pushed_on_readable;
            opCB->on_connected =  private->pushed_on_connected;
            neat_set_operations(opCB->ctx, opCB->flow, opCB);

            // call on_connected
            if (rv == NEAT_OK) {
                opCB->flow->socket->handle->data = opCB->flow->socket;
                opCB->flow->firstWritePending = 1;
                uvpollable_cb(opCB->flow->socket->handle, NEAT_OK, UV_WRITABLE);
            }
            break;
        }
    }
    if (rv != NEAT_OK) {
        neat_io_error(opCB->ctx, opCB->flow, rv);
    }
    return rv;
}

static neat_error_code
handshake(struct neat_ctx *ctx, struct neat_flow *flow,
          struct neat_iofilter *filter, struct neat_tlv optional[], unsigned int opt_count)
{
    neat_error_code rv;
    struct security_data *private;
    private = (struct security_data *) filter->userData;
    if (SSL_is_init_finished(private->ssl)) {
        return NEAT_OK;
    }

    int err = SSL_do_handshake(private->ssl);
    if (err == 1) {
        return NEAT_OK;
    }

    err = SSL_get_error(private->ssl, err);
    if (err == SSL_ERROR_WANT_READ) {
        flow->operations->on_readable = neat_security_handshake;
        flow->operations->on_writable = NULL;
        neat_set_operations(ctx, flow, flow->operations);
    } else if (err == SSL_ERROR_WANT_WRITE) {
        flow->operations->on_writable = neat_security_handshake;
        flow->operations->on_readable = NULL;
        neat_set_operations(ctx, flow, flow->operations);
    } else if (err != SSL_ERROR_NONE) {
        // ERR_print_errors_fp(stderr);
        return NEAT_ERROR_SECURITY;
    }

    if (SSL_is_init_finished(private->ssl)) {
        return NEAT_OK;
    }

    // its possible we now have some tls data (e.g. a client hello in the BIO. Let's write that out
    // to the next filter or the network

    int amtread = BIO_read(private->outputBIO, private->outCipherBuffer, CIPHER_BUFFER_SIZE);
    if (amtread < 0) {
        amtread = 0;
    }
    private->outCipherBufferUsed += amtread;
    rv = drain_output(ctx, flow, filter, optional, opt_count);
    if (rv != NEAT_OK) {
        return rv;
    }

    // its possible we have some tls data from the server (e.g. a server hello) that
    // we need to read from the network and push through the BIO
    rv = gather_input(ctx, flow, filter, optional, opt_count);
    if (rv != NEAT_OK) {
        return rv;
    }
    if (private->inCipherBufferUsed - private->inCipherBufferSent) {
        uint32_t amtWritten = BIO_write(private->inputBIO, private->inCipherBuffer + private->inCipherBufferSent,
                                        private->inCipherBufferUsed - private->inCipherBufferSent);
        if (amtWritten > 0) {
            private->inCipherBufferSent += amtWritten;
        }
        if (private->inCipherBufferUsed == private->inCipherBufferSent) {
            // realistically this should always happen because mem based BIOs expand
            private->inCipherBufferUsed = 0;
            private->inCipherBufferSent = 0;
        }
        flow->operations->on_writable = neat_security_handshake;
        neat_set_operations(ctx, flow, flow->operations);
    }

    return NEAT_ERROR_WOULD_BLOCK;
}

static neat_error_code
neat_security_filter_write(struct neat_ctx *ctx, struct neat_flow *flow,
                           struct neat_iofilter *filter,
                           const unsigned char *buffer, uint32_t amt,
                           struct neat_tlv optional[], unsigned int opt_count)
{
    neat_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);
    neat_error_code rv;
    struct security_data *private;
    private = (struct security_data *) filter->userData;

    if (!SSL_is_init_finished(private->ssl)) {
        rv = handshake(ctx, flow, filter, optional, opt_count);
        if (rv != NEAT_OK) {
            return rv;
        }
    }
    if (!SSL_is_init_finished(private->ssl)) {
        assert (!amt); // should only happen during handshake
        return NEAT_ERROR_WOULD_BLOCK;
    }

    uint32_t written = 0;
    while (written < amt) {
        uint32_t t = SSL_write(private->ssl, buffer + written, amt - written);
        if (t < 1) {
            // the BIOs automatically expand as necessary so
            // this should not fail
            return NEAT_ERROR_SECURITY;
        }
        written += t;
    }

    int amtread;
    while ((amtread = BIO_read(private->outputBIO, private->outCipherBuffer, CIPHER_BUFFER_SIZE)) > 0) {
        private->outCipherBufferUsed = amtread;
        rv = drain_output(ctx, flow, filter, optional, opt_count);
        if (rv != NEAT_OK) {
            return rv;
        }
    }
    return NEAT_OK;
}

static neat_error_code
neat_security_filter_read(struct neat_ctx *ctx, struct neat_flow *flow,
                          struct neat_iofilter *filter,
                          unsigned char *buffer, uint32_t amt,
                          uint32_t *actualAmt,
                          struct neat_tlv optional[], unsigned int opt_count)
{
    neat_log(ctx, NEAT_LOG_DEBUG, "%s %d", __func__, *actualAmt);
    struct security_data *private;
    private = (struct security_data *) filter->userData;
    neat_error_code rv;

    if (!SSL_is_init_finished(private->ssl)) {
        // this should be masked by the handshake code and not happen on client
        assert(flow->isServer);
        rv = handshake(ctx, flow, filter, optional, opt_count);
        if (rv != NEAT_OK) {
            return rv;
        }
    }
    if (!SSL_is_init_finished(private->ssl)){
        return NEAT_ERROR_WOULD_BLOCK;
    }

    // write the ciphertext in buffer/amt into the BIO to decode
    if (BIO_write(private->inputBIO, buffer, *actualAmt) != (int) *actualAmt) {
        return NEAT_ERROR_SECURITY;
    }
    int amtRead = SSL_read(private->ssl, buffer, amt);
    neat_log(ctx, NEAT_LOG_DEBUG, "%s read %d", __func__, amtRead);
    if (amtRead < 0) {
        int err = SSL_get_error(private->ssl, amtRead);
        neat_log(ctx, NEAT_LOG_DEBUG, "%s err %d", __func__, err);
        if (err != SSL_ERROR_NONE && err != SSL_ERROR_WANT_READ &&
            err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_ZERO_RETURN &&
            err != SSL_ERROR_SYSCALL) {
            return NEAT_ERROR_SECURITY;
        }
        return NEAT_ERROR_WOULD_BLOCK;
    }
    *actualAmt = amtRead;
    return NEAT_OK;
}

void tls_init_trust_list(SSL_CTX *ctx);

neat_error_code
neat_security_install(neat_ctx *ctx, neat_flow *flow)
{
    neat_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    // todo list
    // sctp client (via dtls over sctp)
    // sctp server
    // udp client
    // udp server

#if  (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#define client_method() TLS_client_method()
#define server_method() TLS_server_method()
#else
#define client_method() TLSv1_2_client_method()
#define server_method() TLSv1_2_server_method()
#endif

    int isClient = !flow->isServer;
    if (flow->socket->stack == NEAT_STACK_TCP) {
        struct security_data *private = calloc (1, sizeof (struct security_data));
        if (!private)
            return NEAT_ERROR_OUT_OF_MEMORY;
        struct neat_iofilter *filter = insert_neat_iofilter(ctx, flow);
        if (!filter) {
            free(private);
            return NEAT_ERROR_OUT_OF_MEMORY;
        }
        filter->userData = private;
        filter->dtor = neat_security_filter_dtor;
        filter->writefx = neat_security_filter_write;
        filter->readfx = neat_security_filter_read;

        if (isClient) {
            private->ctx = SSL_CTX_new(client_method());
            SSL_CTX_set_verify(private->ctx, SSL_VERIFY_PEER, NULL);
            tls_init_trust_list(private->ctx);
        } else {
            private->ctx = SSL_CTX_new(server_method());
            SSL_CTX_set_ecdh_auto(private->ctx, 1);

            if (!flow->server_pem) {
                neat_log(ctx, NEAT_LOG_ERROR, "PEM file not set via neat_secure_identity()");
                return NEAT_ERROR_SECURITY;
            }

            if ((SSL_CTX_use_certificate_file(private->ctx, flow->server_pem, SSL_FILETYPE_PEM) < 0) ||
                (SSL_CTX_use_PrivateKey_file(private->ctx, flow->server_pem, SSL_FILETYPE_PEM) < 0 )) {
                neat_log(ctx, NEAT_LOG_ERROR, "unable to use cert or private key");
                return NEAT_ERROR_SECURITY;
            }
        }
        // let's disable ssl3 and rc4 as they don't really meet the security bar
        SSL_CTX_set_options(private->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        SSL_CTX_set_cipher_list(private->ctx, "DEFAULT:-RC4");
        private->ssl = SSL_new(private->ctx);

        if (isClient) {
            // authenticate the server.. todo an option to skip
            X509_VERIFY_PARAM *param = SSL_get0_param(private->ssl);
            X509_VERIFY_PARAM_set1_host(param, flow->name, 0);
        }

        private->inputBIO = BIO_new(BIO_s_mem());
        private->outputBIO = BIO_new(BIO_s_mem());
        SSL_set_bio(private->ssl, private->inputBIO, private->outputBIO);
        if (isClient) {
            SSL_set_connect_state(private->ssl);
        } else {
            SSL_set_accept_state(private->ssl);
        }

        SSL_do_handshake(private->ssl);

        private->pushed_on_readable = flow->operations->on_readable;
        private->pushed_on_writable = flow->operations->on_writable;
        private->pushed_on_connected = flow->operations->on_connected;

        // these will eventually be popped back onto the stack when tls is setup
        flow->operations->on_writable = neat_security_handshake;
        flow->operations->on_readable = NULL;
        flow->operations->on_connected = NULL;
        neat_set_operations(ctx, flow, flow->operations);

        flow->socket->handle->data = flow->socket;
        if (isClient) {
            uvpollable_cb(flow->socket->handle, NEAT_OK, UV_WRITABLE);
        }
        return NEAT_OK;
    }

    return NEAT_ERROR_SECURITY;
}

static neat_error_code
dtls_handshake(struct neat_ctx *ctx, struct neat_flow *flow,
        struct neat_tlv optional[], unsigned int opt_count)
{
   // neat_error_code rv;
    struct security_data *private;
    private = (struct security_data *) flow->dtls_data->userData;
    if (SSL_is_init_finished(private->ssl)) {
        return NEAT_OK;
    }

    int err = SSL_do_handshake(private->ssl);
    if (err == 1) {
        return NEAT_OK;
    }

    err = SSL_get_error(private->ssl, err);
    if (err == SSL_ERROR_WANT_READ) {
    printf("SSL_ERROR_WANT_READ\n");
        flow->operations->on_readable = neat_dtls_handshake;
        flow->operations->on_writable = NULL;
        neat_set_operations(ctx, flow, flow->operations);
    } else if (err == SSL_ERROR_WANT_WRITE) {
    printf("SSL_ERROR_WANT_WRITE\n");
        flow->operations->on_writable = neat_dtls_handshake;
        flow->operations->on_readable = NULL;
        neat_set_operations(ctx, flow, flow->operations);
    } else if (err != SSL_ERROR_NONE) {
    printf("other error\n");
        // ERR_print_errors_fp(stderr);
        return NEAT_ERROR_SECURITY;
    }

    if (SSL_is_init_finished(private->ssl)) {
    printf("init is finished\n");
        return NEAT_OK;
    }
    return NEAT_OK;
}

static void
neat_dtls_dtor(struct neat_dtls_data *dtls)
{
    struct security_data *private;
    private = (struct security_data *) dtls->userData;
printf("free dtls\n");
    // private->outputBIO and private->inputBIO are freed by SSL_free(private->ssl)
    if (private && private->ssl) {
        SSL_free(private->ssl);
        private->ssl = NULL;
    }

    if (private && private->ctx) {
        SSL_CTX_free(private->ctx);
        private->ctx = NULL;
    }
    free(private);
    dtls->userData = NULL;
}

static neat_error_code
neat_dtls_write(struct neat_ctx *ctx, struct neat_flow *flow,
                           const unsigned char *buffer, uint32_t amt,
                           struct neat_tlv optional[],
                           unsigned int opt_count)
{
    neat_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);
#if 0
    neat_error_code rv = 0;
    struct security_data *private;
    private = (struct security_data *) flow->dtls_data->userData;
printf("private=%p\n", (void *)private);
    if (!SSL_is_init_finished(private->ssl)) {
    printf("write called but handshake not finished\n");
    printf("state=%d\n", SSL_get_state(private->ssl));
        rv = dtls_handshake(ctx, flow, optional, opt_count);
        if (rv != NEAT_OK) {
            return rv;
        }
    }
    if (!SSL_is_init_finished(private->ssl)) {
        assert (!amt); // should only happen during handshake
        return NEAT_ERROR_WOULD_BLOCK;
    }

    uint32_t written = 0;
    while (written < amt) {
        uint32_t t = SSL_write(private->ssl, buffer + written, amt - written);
        if (t < 1) {
            // the BIOs automatically expand as necessary so
            // this should not fail
            return NEAT_ERROR_SECURITY;
        }
        written += t;
    }
#endif
    return NEAT_OK;
}

static neat_error_code
neat_dtls_read(struct neat_ctx *ctx, struct neat_flow *flow,
                          unsigned char *buffer, uint32_t amt,
                          uint32_t *actualAmt,
                          struct neat_tlv optional[], unsigned int opt_count)
{
    neat_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);
#if 0
    neat_error_code rv = 0;
    struct security_data *private;
    private = (struct security_data *) flow->dtls_data->userData;
    if (!SSL_is_init_finished(private->ssl)) {
        // this should be masked by the handshake code and not happen on client
        assert(flow->isServer);
        rv = dtls_handshake(ctx, flow, optional, opt_count);
        if (rv != NEAT_OK) {
            return rv;
        }
    }
    if (!SSL_is_init_finished(private->ssl)){
        return NEAT_ERROR_WOULD_BLOCK;
    }

    int amtRead = SSL_read(private->ssl, buffer, amt);
    neat_log(ctx, NEAT_LOG_DEBUG, "%s read %d", __func__, amtRead);
    if (amtRead < 0) {
        int err = SSL_get_error(private->ssl, amtRead);
        neat_log(ctx, NEAT_LOG_DEBUG, "%s err %d", __func__, err);
        if (err != SSL_ERROR_NONE && err != SSL_ERROR_WANT_READ &&
            err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_ZERO_RETURN &&
            err != SSL_ERROR_SYSCALL) {
            return NEAT_ERROR_SECURITY;
        }
        return NEAT_ERROR_WOULD_BLOCK;
    }
    *actualAmt = amtRead;
#endif
    return NEAT_OK;
}

static neat_error_code
neat_dtls_handshake(struct neat_flow_operations *opCB)
{
    neat_log(opCB->ctx, NEAT_LOG_DEBUG, "%s", __func__);

    neat_error_code rv = neat_write(opCB->ctx, opCB->flow, NULL, 0, NULL, 0);
    if (rv == NEAT_ERROR_WOULD_BLOCK) {
        return rv;
    }
    neat_log(opCB->ctx, NEAT_LOG_DEBUG, "%s handshake not blocking", __func__);
    struct security_data *private = (struct security_data *) opCB->flow->dtls_data->userData;
    if (SSL_is_init_finished(private->ssl)) {
        printf("DTLS handshake finished\n");
    } else {
        printf("DTLS handshake not finished\n");
    }
    if (opCB->flow->dtls_data->writefx == neat_dtls_write ||
        opCB->flow->dtls_data->readfx == neat_dtls_read) {

        printf("state=%d\n", SSL_get_state(private->ssl));
        // pop application functions back onto stack
        opCB->on_writable = private->pushed_on_writable;
        opCB->on_readable =  private->pushed_on_readable;
        opCB->on_connected =  private->pushed_on_connected;
        neat_set_operations(opCB->ctx, opCB->flow, opCB);

        // call on_connected
        if (rv == NEAT_OK) {
            opCB->flow->socket->handle->data = opCB->flow->socket;
            opCB->flow->firstWritePending = 1;
            uvpollable_cb(opCB->flow->socket->handle, NEAT_OK, UV_WRITABLE);
        }
}
    return rv;
}


neat_error_code
neat_dtls_install(neat_ctx *ctx, struct neat_pollable_socket *sock)
{
    neat_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    struct security_data *private = calloc (1, sizeof (struct security_data));
    struct neat_dtls_data *dtls = calloc (1, sizeof( struct neat_dtls_data));
    dtls->dtor = neat_dtls_dtor;
    dtls->writefx = neat_dtls_write;
    dtls->readfx = neat_dtls_read;
    private->inputBIO = NULL;
    private->outputBIO = NULL;

    printf("private=%p dtls=%p\n", (void *)private, (void *)dtls);

    OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	private->ctx = SSL_CTX_new(DTLSv1_client_method());
	//SSL_CTX_set_cipher_list(private->ctx, "DEFAULT:-RC4");
	SSL_CTX_set_cipher_list(private->ctx, "eNULL:!MD5");
	if (!SSL_CTX_use_certificate_file(private->ctx, "/home/ruengeler/DTLS/client-cert.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(private->ctx, "/home/ruengeler/DTLS/client-key.pem", SSL_FILETYPE_PEM))
		        printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (private->ctx))
		        printf("\nERROR: invalid private key!");
	SSL_CTX_set_verify_depth (private->ctx, 2);
	SSL_CTX_set_read_ahead(private->ctx,1);
    SSL_CTX_set_verify(private->ctx, SSL_VERIFY_PEER, NULL);
	private->ssl = SSL_new(private->ctx);
    X509_VERIFY_PARAM *param = SSL_get0_param(private->ssl);
    X509_VERIFY_PARAM_set1_host(param, sock->flow->name, 0);
	        /* Create DTLS/SCTP BIO and connect */
	printf("make bio\n");
	printf("for socket %d\n", sock->fd);
	private->dtlsBIO = BIO_new_dgram_sctp(sock->fd, BIO_CLOSE);
	/*BIO_ctrl(private->dtlsBIO, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (struct sockaddr *) &(flow->socket->dst_sockaddr));*/
		printf("set bio\n");
    SSL_set_bio(private->ssl, private->dtlsBIO, private->dtlsBIO);

    dtls->userData = private;
    sock->flow->dtls_data = dtls;
    printf("flow->dtls_data->userData=%p\n", (void *)sock->flow->dtls_data->userData);
    return NEAT_OK;
}

neat_error_code
neat_dtls_connect(neat_ctx *ctx, neat_flow *flow)
{
    neat_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    struct security_data *private = (struct security_data *) flow->dtls_data->userData;
    printf("private=%p\n", (void *)private);

  //  SSL_set_connect_state(private->ssl);
printf("3\n");

    private->pushed_on_readable = flow->operations->on_readable;
    private->pushed_on_writable = flow->operations->on_writable;
    private->pushed_on_connected = flow->operations->on_connected;

    // these will eventually be popped back onto the stack when dtls is setup
    flow->operations->on_writable = neat_dtls_handshake;
    flow->operations->on_readable = NULL;
    flow->operations->on_connected = NULL;
    neat_set_operations(ctx, flow, flow->operations);
    SSL_load_error_strings();
printf("call SSL handshake\n");
printf("state=%d\n", SSL_get_state(private->ssl));
    int err = SSL_connect(private->ssl);
        if (err != 1) {
            err = SSL_get_error(private->ssl, err);
            printf("err = %d\n", err);
            printf("state=%d\n", SSL_get_state(private->ssl));
            ERR_print_errors_fp (stderr);
        }

    flow->socket->handle->data = flow->socket;
printf("7\n");
    uvpollable_cb(flow->socket->handle, NEAT_OK, UV_WRITABLE);
    printf("8\n");
    return NEAT_OK;
}

void
neat_security_init(neat_ctx *ctx)
{
    SSL_library_init();
}

void
neat_security_close(neat_ctx *ctx)
{
    FIPS_mode_set(0);
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
    ENGINE_cleanup();
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    ERR_remove_state(0);
#endif
}

#endif

#ifndef NEAT_USETLS
void
neat_security_init(neat_ctx *ctx)
{
}

void
neat_security_close(neat_ctx *ctx)
{
}

neat_error_code
neat_security_install(neat_ctx *ctx, neat_flow *flow)
{
    return NEAT_ERROR_SECURITY;
}

#endif

neat_error_code neat_secure_identity(neat_ctx *ctx, neat_flow *flow, const char *filename)
{
    free(flow->server_pem);
    flow->server_pem = strdup(filename);
    return NEAT_OK;
}
