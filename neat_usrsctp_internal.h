#ifndef NEAT_USRSCTP_INTERNAL
#define NEAT_USRSCTP_INTERNAL


struct neat_ctx *nt_usrsctp_init_ctx(struct neat_ctx *nic);

void neat_usrsctp_close_sockflow(struct neat_flow *fl);

void nt_usrsctp_cleanup(struct neat_ctx *ctx);

void nt_usrsctp_init(struct neat_ctx *ctx);

#endif
