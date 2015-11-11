#include <stdio.h>
#include <assert.h>
#include "neat.h"
#include "neat_internal.h"

static void
he_resolve_cb(struct neat_resolver *resolver, struct neat_resolver_results *results, uint8_t code)
{
    neat_socket *sock = (neat_socket *)resolver->userData1;
    neat_he_callback_fx callback_fx;
    callback_fx = (neat_he_callback_fx) (neat_socket *)resolver->userData2;

    if (code != NEAT_RESOLVER_OK) {
        callback_fx(resolver->nc, (neat_socket *)resolver->userData1, code,
                    0, 0, 0, -1);
        return;
    }

    assert (results->lh_first);
    assert (!sock->resolver_results);

    // right now we're just going to use the first address. Todo by HE folks
    sock->family = results->lh_first->ai_family;
    sock->sockType = results->lh_first->ai_socktype;
    sock->sockProtocol = results->lh_first->ai_protocol;
    sock->resolver_results = results;
    sock->sockAddr = (struct sockaddr *) &(results->lh_first->dst_addr);

    callback_fx(resolver->nc, (neat_socket *)resolver->userData1, NEAT_OK,
                sock->family, sock->sockType, sock->sockProtocol, -1);
}


neat_error_code neat_he_lookup(neat_ctx *ctx, neat_socket *sock, neat_he_callback_fx callback_fx)
{
    if (!ctx->resolver) {
        ctx->resolver = neat_resolver_init(ctx, he_resolve_cb, NULL);
    }
    ctx->resolver->userData1 = (void *)sock;
    ctx->resolver->userData2 = callback_fx;

    // should these items be arguments, or is having them as sock state sensible?
    neat_getaddrinfo(ctx->resolver, AF_INET, sock->name, sock->port,
                     (sock->propertyMask & NEAT_PROPERTY_MESSAGE) ? SOCK_DGRAM : SOCK_STREAM, 0);

    return NEAT_OK;
}

