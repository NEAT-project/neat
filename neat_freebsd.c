#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_core.h"
#include "neat_addr.h"
#include "neat_freebsd.h"
#include "neat_freebsd_internal.h"

static void neat_freebsd_cleanup(struct neat_ctx *nc)
{
    return;
}

struct neat_ctx *neat_freebsd_init_ctx(struct neat_ctx *nc)
{
    nc->cleanup = neat_freebsd_cleanup;
    return nc;
}
