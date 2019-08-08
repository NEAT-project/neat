#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#if defined(NEAT_SCTP_DTLS) && !defined(USRSCTP_SUPPORT)
#include <netinet/sctp.h>
#endif
#include "neat.h"
#include "neat_internal.h"
#include "neat_security.h"

#if defined(NEAT_USETLS) || defined(NEAT_SCTP_DTLS)
//typedef unsigned int bool;
#define true 1
#define false 0

#define BUFFER_SIZE 1<<16

static neat_error_code
neat_dtls_handshake(struct neat_flow_operations *opCB);

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
drain_output(struct neat_ctx *ctx,
             struct neat_flow *flow,
             struct neat_iofilter *filter,
             struct neat_tlv optional[],
             unsigned int opt_count)
{
    neat_error_code rv;
    struct security_data *private;
    private = (struct security_data *) filter->userData;
    int didFilterWrite = 0;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

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
    nt_log(ctx, NEAT_LOG_DEBUG, "wrote out %d cipher text to transport",
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
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    struct security_data *private = (struct security_data *) filter->userData;
    uint32_t actualAmt;
    uint32_t avail = CIPHER_BUFFER_SIZE - private->inCipherBufferUsed;
    if (!avail) {
        return NEAT_ERROR_WOULD_BLOCK;
    }
    neat_error_code rv = flow->readfx(ctx, flow, private->inCipherBuffer + private->inCipherBufferUsed,
                                      avail, &actualAmt, optional, opt_count);
    nt_log(ctx, NEAT_LOG_DEBUG, "read in %d cipher text from transport (%u)",
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
neat_security_filter_write(struct neat_ctx *ctx,
                           struct neat_flow *flow,
                           struct neat_iofilter *filter,
                           const unsigned char *buffer,
                           uint32_t amt,
                           struct neat_tlv optional[],
                           unsigned int opt_count);
static neat_error_code
neat_security_filter_read(struct neat_ctx *ctx,
                          struct neat_flow *flow,
                          struct neat_iofilter *filter,
                          unsigned char *buffer,
                          uint32_t amt,
                          uint32_t *actualAmt,
                          struct neat_tlv optional[],
                          unsigned int opt_count);

static neat_error_code
neat_security_handshake(struct neat_flow_operations *opCB)
{
    nt_log(opCB->ctx, NEAT_LOG_DEBUG, "%s", __func__);
    neat_error_code rv = neat_write(opCB->ctx, opCB->flow, NULL, 0, NULL, 0);
    if (rv == NEAT_ERROR_WOULD_BLOCK) {
        return rv;
    }
    // nt_log(NEAT_LOG_DEBUG, "%s handshake not blocking", __func__);
    for (struct neat_iofilter *filter = opCB->flow->iofilters;
         filter; filter = filter->next) {
        if (filter->writefx == neat_security_filter_write ||
            filter->readfx == neat_security_filter_read) {
            struct security_data *private = (struct security_data *) filter->userData;
            // pop application functions back onto stack
            opCB->on_writable   = private->pushed_on_writable;
            opCB->on_readable   = private->pushed_on_readable;
            opCB->on_connected  = private->pushed_on_connected;
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
        nt_io_error(opCB->ctx, opCB->flow, rv);
    }
    return rv;
}

static neat_error_code
handshake(struct neat_ctx *ctx,
          struct neat_flow *flow,
          struct neat_iofilter *filter,
          struct neat_tlv optional[],
          unsigned int opt_count)
{
    neat_error_code rv;
    struct security_data *private;
    private = (struct security_data *) filter->userData;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (SSL_is_init_finished(private->ssl)) {
        return NEAT_OK;
    }

    int err = SSL_do_handshake(private->ssl);
    if (err == 1) {
        nt_log(ctx, NEAT_LOG_INFO, "%s - handshake successful", __func__);
        return NEAT_OK;
    }

    err = SSL_get_error(private->ssl, err);
    if (err == SSL_ERROR_WANT_READ) {
        flow->operations.on_readable = neat_security_handshake;
        flow->operations.on_writable = NULL;
        neat_set_operations(ctx, flow, &flow->operations);
    } else if (err == SSL_ERROR_WANT_WRITE) {
        flow->operations.on_writable = neat_security_handshake;
        flow->operations.on_readable = NULL;
        neat_set_operations(ctx, flow, &flow->operations);
    } else if (err != SSL_ERROR_NONE) {
        nt_log(ctx, NEAT_LOG_WARNING, "%s - handshake error", __func__);
        ERR_print_errors_fp(stderr);
        return NEAT_ERROR_SECURITY;
    }

    if (SSL_is_init_finished(private->ssl)) {
        nt_log(ctx, NEAT_LOG_WARNING, "%s - SSL_is_init_finished", __func__);
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
        flow->operations.on_writable = neat_security_handshake;
        neat_set_operations(ctx, flow, &flow->operations);
    }

    return NEAT_ERROR_WOULD_BLOCK;
}

static neat_error_code
neat_security_filter_write(struct neat_ctx *ctx,
                           struct neat_flow *flow,
                           struct neat_iofilter *filter,
                           const unsigned char *buffer,
                           uint32_t amt,
                           struct neat_tlv optional[],
                           unsigned int opt_count)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);
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
neat_security_filter_read(struct neat_ctx *ctx,
                          struct neat_flow *flow,
                          struct neat_iofilter *filter,
                          unsigned char *buffer,
                          uint32_t amt,
                          uint32_t *actualAmt,
                          struct neat_tlv optional[],
                          unsigned int opt_count)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s %d", __func__, *actualAmt);
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
    nt_log(ctx, NEAT_LOG_DEBUG, "%s read %d", __func__, amtRead);
    if (amtRead < 0) {
        int err = SSL_get_error(private->ssl, amtRead);
        nt_log(ctx, NEAT_LOG_DEBUG, "%s err %d", __func__, err);
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
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

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
    //ERR_load_crypto_strings();
    //SSL_load_error_strings();

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
            if (!flow->skipCertVerification) {
                SSL_CTX_set_verify(private->ctx, SSL_VERIFY_PEER, NULL);
                tls_init_trust_list(private->ctx);
            }
        } else {
            private->ctx = SSL_CTX_new(server_method());
           // SSL_CTX_set_ecdh_auto(private->ctx, 1); Linux compiler complains

            if (!flow->server_pem) {
                nt_log(ctx, NEAT_LOG_ERROR, "PEM file not set via neat_secure_identity()");
                return NEAT_ERROR_SECURITY;
            }

            if (SSL_CTX_use_certificate_file(private->ctx, flow->server_pem, SSL_FILETYPE_PEM) != 1) {
                nt_log(ctx, NEAT_LOG_ERROR, "unable to use SSL_CTX_use_certificate_file : %s", flow->server_pem);
                ERR_print_errors_fp(stderr);
                return NEAT_ERROR_SECURITY;
            }
            if (SSL_CTX_use_PrivateKey_file(private->ctx, flow->server_pem, SSL_FILETYPE_PEM) != 1) {
                nt_log(ctx, NEAT_LOG_ERROR, "unable to use SSL_CTX_use_PrivateKey_file : %s", flow->server_pem);
                return NEAT_ERROR_SECURITY;
            }
        }
        // let's disable ssl3 and rc4 as they don't really meet the security bar
        SSL_CTX_set_options(private->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        SSL_CTX_set_cipher_list(private->ctx, "DEFAULT:-RC4");
        private->ssl = SSL_new(private->ctx);

        if (!flow->skipCertVerification && isClient) {
            // authenticate the server.. todo an option to skip
            X509_VERIFY_PARAM *param = SSL_get0_param(private->ssl);
            X509_VERIFY_PARAM_set1_host(param, flow->name, 0);
            // support Server Name Indication (SNI)
            SSL_set_tlsext_host_name(private->ssl, flow->name);
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

        private->pushed_on_readable = flow->operations.on_readable;
        private->pushed_on_writable = flow->operations.on_writable;
        private->pushed_on_connected = flow->operations.on_connected;

        // these will eventually be popped back onto the stack when tls is setup
        flow->operations.on_writable = neat_security_handshake;
        flow->operations.on_readable = NULL;
        flow->operations.on_connected = NULL;
        neat_set_operations(ctx, flow, &flow->operations);

        flow->socket->handle->data = flow->socket;
        if (isClient) {
            uvpollable_cb(flow->socket->handle, NEAT_OK, UV_WRITABLE);
        }
        return NEAT_OK;
    }

    if (flow->socket->stack == NEAT_STACK_UDP) {
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
            private->ctx = SSL_CTX_new(DTLS_client_method());
            if (!flow->skipCertVerification) {
                SSL_CTX_set_verify(private->ctx, SSL_VERIFY_PEER, NULL);
                tls_init_trust_list(private->ctx);
            }
        } else {
            private->ctx = SSL_CTX_new(DTLS_server_method());
           // SSL_CTX_set_ecdh_auto(private->ctx, 1); Linux compiler complains

            if (!flow->server_pem) {
                nt_log(ctx, NEAT_LOG_ERROR, "PEM file not set via neat_secure_identity()");
                return NEAT_ERROR_SECURITY;
            }

            if (SSL_CTX_use_certificate_file(private->ctx, flow->server_pem, SSL_FILETYPE_PEM) != 1) {
                nt_log(ctx, NEAT_LOG_ERROR, "unable to use SSL_CTX_use_certificate_file : %s", flow->server_pem);
                ERR_print_errors_fp(stderr);
                return NEAT_ERROR_SECURITY;
            }
            if (SSL_CTX_use_PrivateKey_file(private->ctx, flow->server_pem, SSL_FILETYPE_PEM) != 1) {
                nt_log(ctx, NEAT_LOG_ERROR, "unable to use SSL_CTX_use_PrivateKey_file : %s", flow->server_pem);
                return NEAT_ERROR_SECURITY;
            }
        }
        // let's disable ssl3 and rc4 as they don't really meet the security bar
        SSL_CTX_set_options(private->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        SSL_CTX_set_cipher_list(private->ctx, "DEFAULT:-RC4");
        private->ssl = SSL_new(private->ctx);

        if (!flow->skipCertVerification && isClient) {
            // authenticate the server.. todo an option to skip
            X509_VERIFY_PARAM *param = SSL_get0_param(private->ssl);
            X509_VERIFY_PARAM_set1_host(param, flow->name, 0);
            // support Server Name Indication (SNI)
            SSL_set_tlsext_host_name(private->ssl, flow->name);
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

        private->pushed_on_readable = flow->operations.on_readable;
        private->pushed_on_writable = flow->operations.on_writable;
        private->pushed_on_connected = flow->operations.on_connected;

        // these will eventually be popped back onto the stack when tls is setup
        flow->operations.on_writable = neat_security_handshake;
        flow->operations.on_readable = NULL;
        flow->operations.on_connected = NULL;
        neat_set_operations(ctx, flow, &flow->operations);

        flow->socket->handle->data = flow->socket;

        return NEAT_OK;
    }

    return NEAT_ERROR_SECURITY;
}

#ifdef NEAT_SCTP_DTLS
static void
neat_dtls_dtor(struct neat_dtls_data *dtls)
{
    struct security_data *private;
    private = (struct security_data *) dtls->userData;

    // private->outputBIO and private->inputBIO are freed by SSL_free(private->ssl)
    if (private && private->ssl) {
        SSL_free(private->ssl);
        private->ssl = NULL;
    }

    if (private && private->ctx) {
        SSL_CTX_free(private->ctx);
        private->ctx = NULL;
    }
    if (dtls->userData) {
        free(dtls->userData);
        dtls->userData = NULL;
    }
}

#if !defined(USRSCTP_SUPPORT)
void handle_notifications(BIO *bio, void *context, void *buf) {
    struct sctp_assoc_change *sac;
    struct sctp_send_failed *ssf;
    struct sctp_paddr_change *spc;
    struct sctp_remote_error *sre;
    union sctp_notification *snp = buf;
    char addrbuf[INET6_ADDRSTRLEN];
    const char *ap;
    union {
    struct sockaddr_in s4;
    struct sockaddr_in6 s6;
    struct sockaddr_storage ss;
    } addr;

    switch (snp->sn_header.sn_type) {
        case SCTP_ASSOC_CHANGE:
            sac = &snp->sn_assoc_change;
            printf("NOTIFICATION: assoc_change: state=%hu, error=%hu, instr=%hu outstr=%hu\n",
                sac->sac_state, sac->sac_error, sac->sac_inbound_streams, sac->sac_outbound_streams);
            break;

        case SCTP_PEER_ADDR_CHANGE:
            spc = &snp->sn_paddr_change;
            addr.ss = spc->spc_aaddr;
            if (addr.ss.ss_family == AF_INET) {
                ap = inet_ntop(AF_INET, &addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN);
            } else {
                ap = inet_ntop(AF_INET6, &addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN);
            }
            printf("NOTIFICATION: intf_change: %s state=%d, error=%d\n", ap, spc->spc_state, spc->spc_error);
            break;

        case SCTP_REMOTE_ERROR:
            sre = &snp->sn_remote_error;
            printf("NOTIFICATION: remote_error: err=%hu len=%hu\n", ntohs(sre->sre_error), ntohs(sre->sre_length));
            break;

        case SCTP_SEND_FAILED:
            ssf = &snp->sn_send_failed;
            printf("NOTIFICATION: sendfailed: len=%u err=%d\n", ssf->ssf_length, ssf->ssf_error);
            break;

        case SCTP_SHUTDOWN_EVENT:
            printf("NOTIFICATION: shutdown event\n");
            break;

        case SCTP_ADAPTATION_INDICATION:
            printf("NOTIFICATION: adaptation event\n");
            break;

        case SCTP_PARTIAL_DELIVERY_EVENT:
            printf("NOTIFICATION: partial delivery\n");
            break;

#ifdef SCTP_AUTHENTICATION_EVENT
        case SCTP_AUTHENTICATION_EVENT:
            printf("NOTIFICATION: authentication event\n");
            break;
#endif

#ifdef SCTP_SENDER_DRY_EVENT
        case SCTP_SENDER_DRY_EVENT:
            printf("NOTIFICATION: sender dry event\n");
            break;
#endif

        default:
            printf("NOTIFICATION: unknown type: %hu\n", snp->sn_header.sn_type);
            break;
    }
}
#endif

static neat_error_code
neat_dtls_handshake(struct neat_flow_operations *opCB)
{
    nt_log(opCB->ctx, NEAT_LOG_DEBUG, "%s", __func__);

    struct security_data *private;
    int ret;
    private = (struct security_data *) opCB->flow->socket->dtls_data->userData;

    if (private->state == DTLS_CONNECTING &&
        ((!opCB->flow->isServer && !SSL_in_connect_init(private->ssl)) ||
        ((opCB->flow->isServer && !SSL_in_accept_init(private->ssl))))) {

        nt_log(opCB->ctx, NEAT_LOG_DEBUG, "%s: SSL connection established", __func__);
        private->state = DTLS_CONNECTED;
        opCB->flow->socket->handle->data = opCB->flow->socket;
        opCB->flow->firstWritePending = 0;
        opCB->flow->operations.on_readable = private->pushed_on_readable;
        opCB->flow->operations.on_writable = private->pushed_on_writable;
        opCB->flow->operations.on_connected = NULL;
        neat_set_operations(opCB->ctx, opCB->flow, &opCB->flow->operations);
        uvpollable_cb(opCB->flow->socket->handle, NEAT_OK, UV_WRITABLE | UV_READABLE);
    } else {
        ret = SSL_do_handshake(private->ssl);
        if (ret <= 0) {
            switch (SSL_get_error(private->ssl, ret)) {
                case SSL_ERROR_WANT_READ:
                    uvpollable_cb(opCB->flow->socket->handle, NEAT_OK, UV_READABLE);
                    break;
                case SSL_ERROR_WANT_WRITE:
                    uvpollable_cb(opCB->flow->socket->handle, NEAT_OK, UV_WRITABLE);
                    break;
                default: break;
            }
        }
    }

    return NEAT_OK;
}


neat_error_code
nt_dtls_install(neat_ctx *ctx, struct neat_pollable_socket *sock)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    struct security_data *private   = calloc (1, sizeof (struct security_data));
    struct neat_dtls_data *dtls     = calloc (1, sizeof( struct neat_dtls_data));

    if (!private || !dtls) {
        if (private) {
            free(private);
        }

        if (dtls) {
            free(dtls);
        }

        nt_log(ctx, NEAT_LOG_ERROR, "%s - calloc failed", __func__);
        return NEAT_ERROR_SECURITY;
    }

    dtls->dtor = neat_dtls_dtor;
    private->inputBIO = NULL;
    private->outputBIO = NULL;
    private->state = DTLS_CLOSED;
    sock->flow->firstWritePending = 0;

    int isClient = !(sock->flow->isServer);
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    if (isClient) {
        nt_log(ctx, NEAT_LOG_INFO, "%s - acting as DTLS client", __func__);
        private->ctx = SSL_CTX_new(DTLS_client_method());
        SSL_CTX_set_verify(private->ctx, SSL_VERIFY_NONE, NULL);
        tls_init_trust_list(private->ctx);
    } else {
        nt_log(ctx, NEAT_LOG_INFO, "%s - acting as DTLS server", __func__);
        private->ctx = SSL_CTX_new(DTLS_server_method());
        // SSL_CTX_set_ecdh_auto(private->ctx, 1);

        if (!(sock->flow->cert_pem)) {
            nt_log(ctx, NEAT_LOG_ERROR, "Server certificate file not set via neat_secure_identity()");
            free(dtls);
            free(private);
            return NEAT_ERROR_SECURITY;
        }

        if (!(sock->flow->key_pem)) {
            nt_log(ctx, NEAT_LOG_ERROR, "Server key file not set via neat_secure_identity()");
            free(dtls);
            free(private);
            return NEAT_ERROR_SECURITY;
        }

        int pid = getpid();
        if (!SSL_CTX_set_session_id_context(private->ctx, (void*)&pid, sizeof pid)) {
            perror("SSL_CTX_set_session_id_context");
        }

        if ((SSL_CTX_use_certificate_chain_file(private->ctx, sock->flow->cert_pem) < 0) ||
                (SSL_CTX_use_PrivateKey_file(private->ctx, sock->flow->key_pem, SSL_FILETYPE_PEM) < 0 )) {
            nt_log(ctx, NEAT_LOG_ERROR, "unable to use cert or private key");
            free (dtls);
            free (private);
            return NEAT_ERROR_SECURITY;
        }
    }

    SSL_CTX_set_options(private->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_cipher_list(private->ctx, "DEFAULT:-RC4");

    if (isClient) {
        private->ssl = SSL_new(private->ctx);
        private->dtlsBIO = BIO_new_dgram_sctp(sock->fd, BIO_CLOSE);
        if (private->dtlsBIO == NULL) {
            nt_log(ctx, NEAT_LOG_ERROR, "BIO could not be created. Is AUTH enabled?");
            free (dtls);
            free (private);
            return NEAT_ERROR_SECURITY;
        }
        SSL_set_bio(private->ssl, private->dtlsBIO, private->dtlsBIO);
    } else {
        BIO_new_dgram_sctp(sock->fd, BIO_NOCLOSE);
    }

    dtls->userData = private;
    sock->dtls_data = dtls;
    return NEAT_OK;
}

neat_error_code
nt_dtls_connect(neat_ctx *ctx, neat_flow *flow)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    struct security_data *private = (struct security_data *) flow->socket->dtls_data->userData;

    if (private->state != DTLS_CLOSED) {
        return NEAT_OK;
    }

    private->pushed_on_readable = flow->operations.on_readable;
    private->pushed_on_writable = flow->operations.on_writable;
    private->pushed_on_connected = flow->operations.on_connected;

    SSL_load_error_strings();
  /*  BIO_dgram_sctp_notification_cb(private->dtlsBIO, &handle_notifications, (void*) private->ssl);*/

    if (flow->isServer) {
        SSL_set_accept_state(private->ssl);
    } else {
        SSL_set_connect_state(private->ssl);
    }

    private->state = DTLS_CONNECTING;

    // these will eventually be popped back onto the stack when dtls is setup
    flow->operations.on_writable = neat_dtls_handshake;
    flow->operations.on_readable = neat_dtls_handshake;
    flow->operations.on_connected = NULL;
    neat_set_operations(ctx, flow, &flow->operations);

    flow->socket->handle->data = flow->socket;

    if (flow->isServer) {
        uvpollable_cb(flow->socket->handle, NEAT_OK, UV_READABLE);
    } else {
        uvpollable_cb(flow->socket->handle, NEAT_OK, UV_WRITABLE);
    }
    neat_dtls_handshake(&flow->operations);
    return NEAT_OK;
}

neat_error_code
copy_dtls_data(struct neat_pollable_socket *newSocket, struct neat_pollable_socket *socket)
{
    struct security_data *private   = calloc (1, sizeof(struct security_data));
    struct neat_dtls_data *dtls     = calloc (1, sizeof(struct neat_dtls_data));

    if (!private || !dtls) {
        if (private) {
            free(private);
        }

        if (dtls) {
            free(dtls);
        }

        return NEAT_ERROR_SECURITY;
    }

    dtls->dtor                      = neat_dtls_dtor;
    private->inputBIO               = NULL;
    private->outputBIO              = NULL;
    struct security_data *server    = (struct security_data *) socket->dtls_data->userData;
    private->ctx                    = server->ctx;
    private->ssl                    = server->ssl;
    private->dtlsBIO                = server->dtlsBIO;
    dtls->userData                  = private;
    newSocket->dtls_data            = dtls;

    return NEAT_OK;
}

#endif

void
nt_security_init(neat_ctx *ctx)
{
    SSL_library_init();
}

void
nt_security_close(neat_ctx *ctx)
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
    SSL_COMP_free_compression_methods();
}

#endif

#ifndef NEAT_USETLS
void
nt_security_init(neat_ctx *ctx)
{
}

void
nt_security_close(neat_ctx *ctx)
{
}

neat_error_code
neat_security_install(neat_ctx *ctx, neat_flow *flow)
{
    nt_log(ctx, NEAT_LOG_ERROR, "Library compiled without security support");
    return NEAT_ERROR_SECURITY;
}

#endif

neat_error_code neat_secure_identity(neat_ctx *ctx, neat_flow *flow, const char *filename, int pemType)
{
    switch (pemType) {
        case NEAT_CERT_PEM:
            free(flow->cert_pem);
            flow->cert_pem = strdup(filename);
            break;
        case NEAT_KEY_PEM:
            free(flow->key_pem);
            flow->key_pem = strdup(filename);
            break;
        case NEAT_CERT_KEY_PEM:
            free(flow->server_pem);
            flow->server_pem = strdup(filename);
            break;
    }
    return NEAT_OK;
}
