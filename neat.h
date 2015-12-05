// this is the public API..

#ifndef NEAT_H
#define NEAT_H

#include <sys/types.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

struct neat_ctx; // global
struct neat_flow; // one per connection

struct neat_ctx *neat_init_ctx();
void neat_start_event_loop(struct neat_ctx *nc);
void neat_stop_event_loop(struct neat_ctx *nc);
void neat_free_ctx(struct neat_ctx *nc);

typedef uint64_t neat_error_code;
struct neat_flow_operations;
typedef uint64_t (*neat_flow_operations_fx)(struct neat_flow_operations *);

struct neat_flow_operations
{
  void *userData;

  neat_error_code status;
  neat_flow_operations_fx on_connected;
  neat_flow_operations_fx on_error;
  neat_flow_operations_fx on_readable;
  neat_flow_operations_fx on_writable;

  struct neat_ctx *ctx;
  struct neat_flow *flow;
};

struct neat_flow *neat_new_flow(struct neat_ctx *ctx);
void neat_free_flow(struct neat_flow *flow);

neat_error_code neat_set_operations(struct neat_ctx *ctx, struct neat_flow *flow,
                                    struct neat_flow_operations *ops);
neat_error_code neat_open(struct neat_ctx *ctx, struct neat_flow *flow,
                          const char *name, const char *port); // should port should be int?
neat_error_code neat_read(struct neat_ctx *ctx, struct neat_flow *flow,
                          unsigned char *buffer, uint32_t amt, uint32_t *actualAmt);
neat_error_code neat_write(struct neat_ctx *ctx, struct neat_flow *flow,
                           const unsigned char *buffer, uint32_t amt, uint32_t *actualAmt);
neat_error_code neat_get_property(struct neat_ctx *ctx, struct neat_flow *flow,
                                  uint64_t *outMask);
neat_error_code neat_set_property(struct neat_ctx *ctx, struct neat_flow *flow,
                                  uint64_t inMask);
neat_error_code neat_accept(struct neat_ctx *ctx, struct neat_flow *flow,
                          const char *name, const char *port); // should port should be int?
// do we also need a set property with a void * or an int (e.g. timeouts) or should
// we create higher level named functions for such things?

// for property mask
#define NEAT_PROPERTY_OPTIONAL_SECURITY (1 << 0)
#define NEAT_PROPERTY_REQUIRED_SECURITY (1 << 1)
#define NEAT_PROPERTY_MESSAGE           (1 << 2) // stream is default
#define NEAT_PROPERTY_IPV6_REQUIRED     (1 << 3)
#define NEAT_PROPERTY_IPV6_BANNED       (1 << 4)
#define NEAT_PROPERTY_SCTP_REQUIRED     (1 << 5)
#define NEAT_PROPERTY_SCTP_BANNED       (1 << 6)

#define NEAT_ERROR_OK (0)
#define NEAT_OK NEAT_ERROR_OK
#define NEAT_ERROR_WOULD_BLOCK (1)
#define NEAT_ERROR_BAD_ARGUMENT (2)
#define NEAT_ERROR_IO (3)
#define NEAT_ERROR_DNS (4)
#define NEAT_ERROR_INTERNAL (5)
#define NEAT_ERROR_SECURITY (6)
#define NEAT_ERROR_UNABLE (7)

// cleanup extern "C"
#ifdef __cplusplus
}
#endif
#endif // guard bars
