#include <stdio.h>
#include <stdlib.h>

#include "neat_core.h"

int main(int argc, char *argv[])
{
    struct neat_ctx *nc = neat_alloc_ctx();

    if (nc == NULL)
        exit(EXIT_FAILURE);

    if (nc->init(nc)) {
        neat_free_ctx(nc);
        exit(EXIT_FAILURE);
    }

    neat_start_event_loop(nc);

    neat_free_ctx(nc);
    exit(EXIT_SUCCESS);
}
