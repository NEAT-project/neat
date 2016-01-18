
#define NEAT_TURN_SERVER_IP 139.133.204.18
#define NEAT_TURN_SERVER_PORT 3478

static neat_error_code
neat_write_via_turn(struct neat_ctx *ctx, struct neat_flow *flow,
                      const unsigned char *buffer, uint32_t amt);

static neat_error_code
neat_read_via_turn(struct neat_ctx *ctx, struct neat_flow *flow,
                     unsigned char *buffer, uint32_t amt, uint32_t *actualAmt);

static int
neat_accept_via_turn(struct neat_ctx *ctx, struct neat_flow *flow, int fd);

static int
neat_connect_via_turn(struct neat_ctx *ctx, struct neat_flow *flow);

static int
neat_close_via_turn(struct neat_ctx *ctx, struct neat_flow *flow);

static int
neat_listen_via_turn(struct neat_ctx *ctx, struct neat_flow *flow);

