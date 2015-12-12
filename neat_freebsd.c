#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_addr.h"

static void neat_freebsd_get_addresses(struct neat_ctx *ctx)
{
    struct ifaddrs *ifp, *ifa;
    struct in6_ifreq ifr6;
    struct sockaddr_dl *sdl;
    char *cached_ifname;
    unsigned short cached_ifindex;
    uint32_t preferred_lifetime, valid_lifetime;

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
        if (ifa->ifa_addr->sa_family == AF_INET) {
            preferred_lifetime = 0;
            valid_lifetime = 0;
        } else {
            strncpy(ifr6.ifr_name, cached_ifname, IF_NAMESIZE);
            memcpy(&ifr6.ifr_addr, ifa->ifa_addr, sizeof(struct sockaddr_in6));
            if (ioctl(ctx->udp6_fd, SIOCGIFALIFETIME_IN6, &ifr6) < 0) {
                fprintf(stderr,
                        "neat_freebsd_get_addresses: can't determine lifetime of address\n");
            }
            preferred_lifetime = ifr6.ifr_ifru.ifru_lifetime.ia6t_pltime;
            valid_lifetime = ifr6.ifr_ifru.ifru_lifetime.ia6t_vltime;
        }
        neat_addr_update_src_list(ctx,
                                  (struct sockaddr_storage *)ifa->ifa_addr,
                                  cached_ifindex,
                                  1,
                                  preferred_lifetime,
                                  valid_lifetime);
    }
    freeifaddrs(ifp);
}

#define NEAT_ROUTE_BUFFER_SIZE 8192

static void neat_freebsd_route_alloc(uv_handle_t *handle,
                                     size_t suggested_size,
                                     uv_buf_t *buf)
{
    struct neat_ctx *ctx;

    ctx = handle->data;
    memset(ctx->route_buf, 0, NEAT_ROUTE_BUFFER_SIZE);
    buf->base = ctx->route_buf;
    buf->len = NEAT_ROUTE_BUFFER_SIZE;
}

#define ROUNDUP(a, size) (((a) & ((size)-1)) ? (1 + ((a) | ((size)-1))) : (a))
#define NEXT_SA(ap) ap = (struct sockaddr *) \
        ((caddr_t) ap + (ap->sa_len ? ROUNDUP(ap->sa_len, sizeof (uint32_t)) : sizeof(uint32_t)))

static void neat_freebsd_get_rtaddrs(int addrs,
                                     struct sockaddr *sa,
                                     struct sockaddr **rti_info)
{
    int i;

    for (i = 0; i < RTAX_MAX; i++) {
        if (addrs & (1 << i)) {
            rti_info[i] = sa;
                NEXT_SA(sa);
        } else {
            rti_info[i] = NULL;
        }
    }
}

static void neat_freebsd_route_recv(uv_udp_t *handle,
                                    ssize_t nread,
                                    const uv_buf_t *buf,
                                    const struct sockaddr *addr,
                                    unsigned int flags)
{
    struct neat_ctx *ctx;
    struct ifa_msghdr *ifa;
    struct in6_ifreq ifr6;
    struct sockaddr *sa, *rti_info[RTAX_MAX];
    char if_name[IF_NAMESIZE];
    uint32_t preferred_lifetime, valid_lifetime;

    ctx = (struct neat_ctx *)handle->data;
    ifa = (struct ifa_msghdr *)buf->base;
    if ((ifa->ifam_type != RTM_NEWADDR) && (ifa->ifam_type != RTM_DELADDR)) {
        return;
    }
    sa = (struct sockaddr *) (ifa + 1);
    neat_freebsd_get_rtaddrs(ifa->ifam_addrs, sa, rti_info);
    if (rti_info[RTAX_IFA]->sa_family == AF_INET) {
        preferred_lifetime = 0;
        valid_lifetime = 0;
    } else {
        if (if_indextoname(ifa->ifam_index, if_name) == NULL) {
            fprintf(stderr,
                    "neat_freebsd_get_addresses: can't determine name of interface with index %u\n",
                    ifa->ifam_index);
            return;
        }
        strncpy(ifr6.ifr_name, if_name, IF_NAMESIZE);
        memcpy(&ifr6.ifr_addr, rti_info[RTAX_IFA], sizeof(struct sockaddr_in6));
        if (ioctl(ctx->udp6_fd, SIOCGIFALIFETIME_IN6, &ifr6) < 0) {
            fprintf(stderr,
                    "neat_freebsd_get_addresses: can't determine lifetime of address\n");
            return;
        }
        preferred_lifetime = ifr6.ifr_ifru.ifru_lifetime.ia6t_pltime;
        valid_lifetime = ifr6.ifr_ifru.ifru_lifetime.ia6t_vltime;
        }
    neat_addr_update_src_list(ctx,
                              (struct sockaddr_storage *)rti_info[RTAX_IFA],
                              ifa->ifam_index,
                              ifa->ifam_type == RTM_NEWADDR ? 1 : 0,
                              preferred_lifetime,
                              valid_lifetime);
}

static void neat_freebsd_cleanup(struct neat_ctx *ctx)
{
    if (ctx->route_fd >= 0) {
        close(ctx->route_fd);
    }
    if (ctx->udp6_fd >= 0) {
        close(ctx->udp6_fd);
    }
    free(ctx->route_buf);
    return;
}

struct neat_ctx *neat_freebsd_init_ctx(struct neat_ctx *ctx)
{
    int ret;

    ctx->route_fd = -1;
    ctx->route_buf = NULL;
    ctx->cleanup = neat_freebsd_cleanup;

    if ((ctx->udp6_fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr,
                "neat_freebsd_init_ctx: can't open UDP/IPv6 socket (%s)\n",
                strerror(errno));
    }
    if ((ctx->route_buf = malloc(NEAT_ROUTE_BUFFER_SIZE)) == NULL) {
        fprintf(stderr,
                "neat_freebsd_init_ctx: can't allocate buffer\n");
        neat_free_ctx(ctx);
        return NULL;
    }
    if ((ctx->route_fd = socket(AF_ROUTE, SOCK_RAW, 0)) < 0) {
        fprintf(stderr,
                "neat_freebsd_init_ctx: can't open routing socket (%s)\n",
                strerror(errno));
        neat_free_ctx(ctx);
        return NULL;
    }
    /* routing sockets can be handled like UDP sockets by uv */
    if ((ret = uv_udp_init(ctx->loop, &(ctx->uv_route_handle))) < 0) {
        fprintf(stderr,
                "neat_freebsd_init_ctx: can't initialize routing handle (%s)\n",
                uv_strerror(ret));
        neat_free_ctx(ctx);
        return NULL;
    }
    ctx->uv_route_handle.data = ctx;
    if ((ret = uv_udp_open(&(ctx->uv_route_handle), ctx->route_fd)) < 0) {
        fprintf(stderr,
                "neat_freebsd_init_ctx: can't add routing handle (%s)\n",
                uv_strerror(ret));
        neat_free_ctx(ctx);
        return NULL;
    }
    if ((ret = uv_udp_recv_start(&(ctx->uv_route_handle),
                                 neat_freebsd_route_alloc,
                                 neat_freebsd_route_recv)) < 0) {
        fprintf(stderr,
                "neat_freebsd_init_ctx: can't start receiving route changes (%s)\n",
                uv_strerror(ret));
        neat_free_ctx(ctx);
        return NULL;
    }
    neat_freebsd_get_addresses(ctx);
    return ctx;
}
