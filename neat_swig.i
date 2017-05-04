/* NEAT declarations for SWIG */
%module neat
%{
/*#define SWIG_FILE_WITH_INIT*/
#include "neat.h"
%}

extern struct neat_ctx *neat_init_ctx();
extern struct neat_flow *neat_new_flow(struct neat_ctx *ctx);
extern neat_error_code neat_start_event_loop(struct neat_ctx *nc, neat_run_mode run_mode);
extern void neat_free_ctx(struct neat_ctx *nc);

extern neat_error_code neat_open(struct neat_ctx *mgr, struct neat_flow *flow,
                          const char *name, uint16_t port,
                          struct neat_tlv optional[], unsigned int opt_count);

extern neat_error_code neat_set_operations(struct neat_ctx *ctx,
                                                struct neat_flow *flow,
                                                struct neat_flow_operations *ops);

extern neat_error_code neat_set_property(struct neat_ctx *ctx, struct neat_flow *flow,
                                              const char* properties);
