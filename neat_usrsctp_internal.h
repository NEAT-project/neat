#ifndef NEAT_USRSCTP_INTERNAL
#define NEAT_USRSCTP_INTERNAL


struct neat_ctx *neat_usrsctp_init_ctx(struct neat_ctx *nic);

void neat_usrsctp_close_sockflow(struct neat_flow *fl);

#endif
