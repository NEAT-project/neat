#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#if !defined(__NetBSD__)
#include <net/if_var.h>
#endif
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <sys/ioctl.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_addr.h"

/* On FreeBSD the number of seconds since booting is used.
   On other platforms, the number of seconds since 1.1.1970 is used. */
static time_t
neat_time(void)
{
#ifdef __FreeBSD__
     struct timespec now;

    clock_gettime(CLOCK_MONOTONIC_FAST, &now);
    return (now.tv_sec);
#else
   return (time(NULL));
#endif
}

static void neat_bsd_get_addresses(struct neat_ctx *ctx)
{
    struct ifaddrs *ifp, *ifa;
    struct in6_ifreq ifr6;
    struct sockaddr_dl *sdl;
    char *cached_ifname;
    unsigned short cached_ifindex;
    time_t now;
    struct in6_addrlifetime *lifetime;
    uint32_t preferred_lifetime, valid_lifetime;

    if (getifaddrs(&ifp) < 0) {
        neat_log(NEAT_LOG_ERROR,
                "%s: getifaddrs() failed: %s", __func__, strerror(errno));
        return;
    }
    now = neat_time();
    cached_ifname = "";
    cached_ifindex = 0;
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
                neat_log(NEAT_LOG_ERROR,
                        "%s: can't determine index of interface %.*s",
                        __func__, IF_NAMESIZE, ifa->ifa_name);
                continue;
            }
        }
        if (ifa->ifa_addr->sa_family == AF_INET) {
            preferred_lifetime = 0;
            valid_lifetime = 0;
        } else {
            memset(&ifr6, 0, sizeof(struct in6_ifreq));
            strncpy(ifr6.ifr_name, cached_ifname, IF_NAMESIZE);
            memcpy(&ifr6.ifr_addr, ifa->ifa_addr, sizeof(struct sockaddr_in6));
            if (ioctl(ctx->udp6_fd, SIOCGIFALIFETIME_IN6, &ifr6) < 0) {
                neat_log(NEAT_LOG_ERROR,
                        "%s: can't determine lifetime of address", __func__);
            }
            lifetime = &ifr6.ifr_ifru.ifru_lifetime;
            if (lifetime->ia6t_preferred == 0) {
                preferred_lifetime = NEAT_UNLIMITED_LIFETIME;
            } else if (lifetime->ia6t_preferred > now) {
                preferred_lifetime = lifetime->ia6t_preferred - now;
            } else {
                preferred_lifetime = 0;
            }
            if (lifetime->ia6t_expire == 0) {
                valid_lifetime = NEAT_UNLIMITED_LIFETIME;
            } else if (lifetime->ia6t_expire > now) {
                valid_lifetime = lifetime->ia6t_expire - now;
            } else {
                valid_lifetime = 0;
            }
        }
        neat_addr_update_src_list(ctx,
                                  (struct sockaddr_storage *)ifa->ifa_addr,
                                  cached_ifindex,
                                  1,
                                  0,
                                  preferred_lifetime,
                                  valid_lifetime);
    }
    freeifaddrs(ifp);
}

#define NEAT_ROUTE_BUFFER_SIZE 8192

static void neat_bsd_route_alloc(uv_handle_t *handle,
                                 size_t suggested_size,
                                 uv_buf_t *buf)
{
    struct neat_ctx *ctx;

    ctx = handle->data;
    memset(ctx->route_buf, 0, NEAT_ROUTE_BUFFER_SIZE);
    buf->base = ctx->route_buf;
    buf->len = NEAT_ROUTE_BUFFER_SIZE;
}

#if defined(__APPLE__)
#define ROUNDUP32(a) \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof (uint32_t) - 1))) : sizeof (uint32_t))
#define SA_SIZE(sa) ROUNDUP32((sa)->sa_len)
#endif
#if defined(__NetBSD__)
#define SA_SIZE(sa) RT_ROUNDUP((sa)->sa_len)
#endif

static void neat_bsd_get_rtaddrs(int addrs,
                                 caddr_t buf,
                                 struct sockaddr *rti_info[])
{
    struct sockaddr *sa;
    int i;

    for (i = 0; i < RTAX_MAX; i++) {
        if (addrs & (1 << i)) {
            sa = (struct sockaddr *)buf;
            rti_info[i] = sa;
            buf += SA_SIZE(sa);
        } else {
            rti_info[i] = NULL;
        }
    }
}

static void neat_bsd_route_recv(uv_udp_t *handle,
                                ssize_t nread,
                                const uv_buf_t *buf,
                                const struct sockaddr *addr,
                                unsigned int flags)
{
    struct neat_ctx *ctx;
    struct ifa_msghdr *ifa;
    struct in6_ifreq ifr6;
    struct sockaddr *rti_info[RTAX_MAX];
    char if_name[IF_NAMESIZE];
    char addr_str_buf[INET6_ADDRSTRLEN];
    const char *addr_str;
    time_t now;
    struct in6_addrlifetime *lifetime;
    uint32_t preferred_lifetime, valid_lifetime;

    ctx = (struct neat_ctx *)handle->data;
    ifa = (struct ifa_msghdr *)buf->base;
    if ((ifa->ifam_type != RTM_NEWADDR) && (ifa->ifam_type != RTM_DELADDR)) {
        return;
    }
    neat_bsd_get_rtaddrs(ifa->ifam_addrs, (caddr_t)(ifa + 1), rti_info);
    if ((rti_info[RTAX_IFA]->sa_family == AF_INET) ||
        (ifa->ifam_type == RTM_DELADDR)) {
        preferred_lifetime = 0;
        valid_lifetime = 0;
    } else {
        if (if_indextoname(ifa->ifam_index, if_name) == NULL) {
            neat_log(NEAT_LOG_ERROR,
                    "%s: can't determine name of interface with index %u",
                    __func__, ifa->ifam_index);
            return;
        }
        lifetime = &ifr6.ifr_ifru.ifru_lifetime;
        strncpy(ifr6.ifr_name, if_name, IF_NAMESIZE);
        memcpy(&ifr6.ifr_addr, rti_info[RTAX_IFA], sizeof(struct sockaddr_in6));
        if (ioctl(ctx->udp6_fd, SIOCGIFALIFETIME_IN6, &ifr6) < 0) {
            addr_str = inet_ntop(AF_INET6, rti_info[RTAX_IFA], addr_str_buf, INET6_ADDRSTRLEN);
            neat_log(NEAT_LOG_ERROR,
                    "%s: can't determine lifetime of address %s (%s)",
                    __func__, addr_str ? addr_str : "Invalid IPv6 address", strerror(errno));
            return;
        }
        now = neat_time();
        if (lifetime->ia6t_preferred == 0) {
            preferred_lifetime = NEAT_UNLIMITED_LIFETIME;
        } else if (lifetime->ia6t_preferred > now) {
            preferred_lifetime = lifetime->ia6t_preferred - now;
        } else {
            preferred_lifetime = 0;
        }
        if (lifetime->ia6t_expire == 0) {
            valid_lifetime = NEAT_UNLIMITED_LIFETIME;
        } else if (lifetime->ia6t_expire > now) {
             valid_lifetime = lifetime->ia6t_expire - now;
        } else {
            valid_lifetime = 0;
        }
    }
    neat_addr_update_src_list(ctx,
                              (struct sockaddr_storage *)rti_info[RTAX_IFA],
                              ifa->ifam_index,
                              ifa->ifam_type == RTM_NEWADDR ? 1 : 0,
                              0,
                              preferred_lifetime,
                              valid_lifetime);
}

static void neat_bsd_cleanup(struct neat_ctx *ctx)
{
    if (ctx->route_fd >= 0) {
        close(ctx->route_fd);
    }
    if (ctx->udp6_fd >= 0) {
        close(ctx->udp6_fd);
    }
    if (ctx->route_buf) {
        free(ctx->route_buf);
    }
    return;
}

struct neat_ctx *neat_bsd_init_ctx(struct neat_ctx *ctx)
{
    int ret;

    ctx->route_fd = -1;
    ctx->route_buf = NULL;
    ctx->cleanup = neat_bsd_cleanup;

    if ((ctx->udp6_fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        neat_log(NEAT_LOG_ERROR,
                "%s: can't open UDP/IPv6 socket (%s)", __func__,
                strerror(errno));
    }
    if ((ctx->route_buf = malloc(NEAT_ROUTE_BUFFER_SIZE)) == NULL) {
        neat_log(NEAT_LOG_ERROR,
                "%s: can't allocate buffer");
        neat_bsd_cleanup(ctx);
        return NULL;
    }
    if ((ctx->route_fd = socket(AF_ROUTE, SOCK_RAW, 0)) < 0) {
        neat_log(NEAT_LOG_ERROR,
                "%s: can't open routing socket (%s)", __func__,
                strerror(errno));
        neat_bsd_cleanup(ctx);
        return NULL;
    }
    /* routing sockets can be handled like UDP sockets by uv */
    if ((ret = uv_udp_init(ctx->loop, &(ctx->uv_route_handle))) < 0) {
        neat_log(NEAT_LOG_ERROR,
                "%s: can't initialize routing handle (%s)", __func__,
                uv_strerror(ret));
        neat_bsd_cleanup(ctx);
        return NULL;
    }
    ctx->uv_route_handle.data = ctx;
    if ((ret = uv_udp_open(&(ctx->uv_route_handle), ctx->route_fd)) < 0) {
        neat_log(NEAT_LOG_ERROR,
                "%s: can't add routing handle (%s)", __func__,
                uv_strerror(ret));
        neat_bsd_cleanup(ctx);
        return NULL;
    }
    if ((ret = uv_udp_recv_start(&(ctx->uv_route_handle),
                                 neat_bsd_route_alloc,
                                 neat_bsd_route_recv)) < 0) {
        neat_log(NEAT_LOG_ERROR,
                "%s: can't start receiving route changes (%s)", __func__,
                uv_strerror(ret));
        neat_bsd_cleanup(ctx);
        return NULL;
    }
    neat_bsd_get_addresses(ctx);
    return ctx;
}
