#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <ifaddrs.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_addr.h"

static void neat_freebsd_get_addresses(struct neat_ctx *ctx)
{
    struct ifaddrs *ifp, *ifa;
    struct sockaddr_dl *sdl;
    char *cached_ifname;
    unsigned short cached_ifindex;

    if (getifaddrs(&ifp) < 0) {
        fprintf(stderr,
                "neat_freebsd_get_addresses: getifaddrs() failed: %s\n",
                strerror(errno));
        return;
    }
    for (ifa = ifp; ifa != NULL; ifa = ifa->ifa_next) {
        /*
         * FreeBSD reports the interface index as part of the AF_LINK address.
         * Since AF_LINK addresses are reported before AF_INET and AF_INET6
         * addresses, cache the interface index.
         */
        if (ifa->ifa_addr->sa_family == AF_LINK) {
            sdl = (struct sockaddr_dl *)ifa->ifa_addr;
            cached_ifindex = sdl->sdl_index;
            cached_ifname = ifa->ifa_name;
        }
        if (ifa->ifa_addr->sa_family != AF_INET &&
            ifa->ifa_addr->sa_family != AF_INET6) {
            continue;
        }
        /* If the cached value is not the one needed, do a full search. TSNH */
        if (strncmp(ifa->ifa_name, cached_ifname, IF_NAMESIZE) != 0) {
            struct ifaddrs *lifa;

            for (lifa = ifp; lifa != NULL; lifa = lifa->ifa_next) {
                if (lifa->ifa_addr->sa_family != AF_LINK) {
                    continue;
                }
                if (strncmp(ifa->ifa_name, lifa->ifa_name, IF_NAMESIZE) == 0) {
                    sdl = (struct sockaddr_dl *)lifa->ifa_addr;
                    cached_ifindex = sdl->sdl_index;
                    cached_ifname = ifa->ifa_name;
                    break;
                }
            }
            /* If we can't determine the interface index, skip this address. */
            if (lifa == NULL) {
                fprintf(stderr,
                        "neat_freebsd_get_addresses: can't determine index of interface %.*s\n",
                        IF_NAMESIZE, ifa->ifa_name);
                continue;
            }
        }
        neat_addr_update_src_list(ctx,
                                  (struct sockaddr_storage *)ifa->ifa_addr,
                                  cached_ifindex,
                                  1,
                                  0,  /* XXX: ifa_pref */
                                  0); /* XXX: ifa_valid */
    }
    freeifaddrs(ifp);
}

static void neat_freebsd_cleanup(struct neat_ctx *ctx)
{
    return;
}

struct neat_ctx *neat_freebsd_init_ctx(struct neat_ctx *ctx)
{
    neat_freebsd_get_addresses(ctx);
    ctx->cleanup = neat_freebsd_cleanup;
    return ctx;
}
