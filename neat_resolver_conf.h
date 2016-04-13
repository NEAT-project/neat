#ifndef NEAT_RESOLVER_CONF_H
#define NEAT_RESOLVER_CONF_H

#include <uv.h>

struct neat_resolver;

uint8_t neat_resolver_add_initial_servers(struct neat_resolver *resolver);
void neat_resolver_resolv_conf_updated(uv_fs_event_t *handle,
        const char *filename, int events, int status);

#endif
