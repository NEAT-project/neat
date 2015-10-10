#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>

#include "neat.h"
#include "neat_core.h"
#include "neat_addr.h"
#include "neat_resolver.h"

static void neat_resolver_handle_newaddr(struct neat_internal_ctx *nic,
                                         void *data)
{
    struct neat_src_addr *src_addr = data;
    char addr_str[INET6_ADDRSTRLEN];

    if (src_addr->family == AF_INET)
        inet_ntop(AF_INET, &(src_addr->u.v4.addr4), addr_str, INET6_ADDRSTRLEN);
    else
        inet_ntop(AF_INET6, &(src_addr->u.v6.addr6), addr_str,
                INET6_ADDRSTRLEN);

    printf("New addr %s\n", addr_str);
}

static void neat_resolver_handle_updateaddr(struct neat_internal_ctx *nic,
                                            void *data)
{
    struct neat_src_addr *src_addr = data;
    char addr_str[INET6_ADDRSTRLEN];

    if (src_addr->family == AF_INET)
        inet_ntop(AF_INET, &(src_addr->u.v4.addr4), addr_str, INET6_ADDRSTRLEN);
    else
        inet_ntop(AF_INET6, &(src_addr->u.v6.addr6), addr_str,
                INET6_ADDRSTRLEN);

    printf("Updated %s\n", addr_str);
}

static void neat_resolver_handle_deladdr(struct neat_internal_ctx *nic,
                                         void *data)
{
    struct neat_src_addr *src_addr = data;
    char addr_str[INET6_ADDRSTRLEN];

    if (src_addr->family == AF_INET)
        inet_ntop(AF_INET, &(src_addr->u.v4.addr4), addr_str, INET6_ADDRSTRLEN);
    else
        inet_ntop(AF_INET6, &(src_addr->u.v6.addr6), addr_str,
                INET6_ADDRSTRLEN);

    printf("Deleted %s\n", addr_str);
}

static struct neat_resolver* neat_resolve_create(struct neat_internal_ctx *nic)
{
    struct neat_resolver *resolver = calloc(sizeof(struct neat_resolver), 1);

    if (!resolver) {
        fprintf(stderr, "Could not allocate memory for resolver\n");
        return NULL;
    }

    
    resolver->newaddr_cb.event_cb = neat_resolver_handle_newaddr;
    resolver->updateaddr_cb.event_cb = neat_resolver_handle_updateaddr;
    resolver->deladdr_cb.event_cb = neat_resolver_handle_deladdr;

    if (neat_add_event_cb(nic, NEAT_NEWADDR, &(resolver->newaddr_cb)) ||
        neat_add_event_cb(nic, NEAT_UPDATEADDR, &(resolver->updateaddr_cb)) ||
        neat_add_event_cb(nic, NEAT_DELADDR, &(resolver->deladdr_cb))) {
        fprintf(stderr, "Could not add one or more resolver callbacks\n");
        free(resolver);
        return NULL;
    }

    return resolver;
}

uint8_t neat_getaddrinfo(struct neat_ctx *nc, const char *service)
{
    struct neat_internal_ctx *nic = (struct neat_internal_ctx*) nc;

    //For now, just register callbacks
    if (!nic->resolver) {
        nic->resolver = neat_resolve_create(nic);

        //TODO: Decide what to do here
        assert(nic->resolver != NULL);
    }

    return RETVAL_SUCCESS;
}

