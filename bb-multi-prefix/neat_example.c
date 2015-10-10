#include <stdio.h>
#include <stdlib.h>

#include "neat.h"

int main(int argc, char *argv[])
{
    struct neat_ctx *nc = neat_alloc_ctx();

    if (nc == NULL)
        exit(EXIT_FAILURE);

    if (neat_init_ctx(nc)) {
        neat_free_ctx(nc);
        exit(EXIT_FAILURE);
    }

    neat_getaddrinfo(nc, "abcd");
    neat_start_event_loop(nc);

    neat_free_ctx(nc);
    exit(EXIT_SUCCESS);
}
