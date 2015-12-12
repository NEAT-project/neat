#ifndef NEAT_FREEBSD_H
#define NEAT_FREEBSD_H

// FreeBSD internal information, all related to routing sockets
#define NEAT_INTERNAL_OS \
    int route_fd; \
    int udp6_fd; \
    uv_udp_t uv_route_handle; \
    char *route_buf

#endif
