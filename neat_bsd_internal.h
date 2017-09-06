#ifndef NEAT_FREEBSD_INTERNAL
#define NEAT_FREEBSD_INTERNAL

struct neat_ctx *nt_bsd_init_ctx(struct neat_ctx *nic);

/* Get statistics from BSD TCP_INFO */
int bsd_get_tcp_info(struct neat_flow * , struct neat_tcp_info *);

#endif
