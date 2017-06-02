/* NEAT declarations for SWIG */
%module neat
%{
/*#define SWIG_FILE_WITH_INIT*/
#include "neat.h"
%}

%include "stdint.i"

typedef enum {
    NEAT_RUN_DEFAULT = 0,
    NEAT_RUN_ONCE,
    NEAT_RUN_NOWAIT
} neat_run_mode;

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

extern neat_error_code neat_accept(struct neat_ctx *ctx, struct neat_flow *flow,
                            uint16_t port, struct neat_tlv optional[], unsigned int opt_count);

extern struct neat_flow_operations {
    void *userData;

    neat_error_code status;
    int stream_id;
    neat_flow_operations_fx on_connected;
    neat_flow_operations_fx on_error;
    neat_flow_operations_fx on_readable;
    neat_flow_operations_fx on_writable;
    neat_flow_operations_fx on_all_written;
    neat_flow_operations_fx on_network_status_changed;
    neat_flow_operations_fx on_aborted;
    neat_flow_operations_fx on_timeout;
    neat_flow_operations_fx on_close;
    neat_cb_send_failure_t on_send_failure;
    neat_cb_flow_slowdown_t on_slowdown;
    neat_cb_flow_rate_hint_t on_rate_hint;

    struct neat_ctx *ctx;
    struct neat_flow *flow;
};
