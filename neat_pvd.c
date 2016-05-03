#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_resolver.h"
#include "neat_core.h"
#include "neat_pvd.h"

static void neat_pvd_handle_newaddr(struct neat_ctx *nc,
                                         void *p_ptr,
                                         void *data)
{

}

struct neat_pvd *
neat_pvd_init(struct neat_ctx *nc)
{
    struct neat_pvd *pvd = calloc(sizeof(struct neat_pvd), 1);
    if (!pvd)
        return NULL;

    pvd->nc = nc;

    pvd->newaddr_cb.event_cb = neat_pvd_handle_newaddr;
    pvd->newaddr_cb.data = pvd;

    if (neat_add_event_cb(nc, NEAT_NEWADDR, &(pvd->newaddr_cb))) {
        neat_log(NEAT_LOG_ERROR, "%s - Could not add one pvd callbacks", __func__);
        return NULL;
    }

    return pvd;
}
