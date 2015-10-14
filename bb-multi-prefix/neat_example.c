#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "neat.h"

void resolver_cleanup(struct neat_resolver *resolver)
{
    printf("Cleanup function\n");
    free(resolver);
}

int main(int argc, char *argv[])
{
    struct neat_ctx *nc = calloc(sizeof(struct neat_ctx), 1);
    struct neat_resolver *resolver = calloc(sizeof(struct neat_resolver), 1);

    if (nc == NULL || resolver == NULL)
        exit(EXIT_FAILURE);
   
    if (neat_init_ctx(nc) ||
        neat_resolver_init(nc, resolver, resolver_cleanup)) {
        free(nc);
        free(resolver);
        exit(EXIT_FAILURE);
    }

    if (neat_getaddrinfo(resolver, AF_UNSPEC, "www.google.com"))
        exit(EXIT_FAILURE);

    neat_start_event_loop(nc);

    neat_free_ctx(nc);
    exit(EXIT_SUCCESS);
}
