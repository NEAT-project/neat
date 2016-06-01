// this is the public API..

#ifndef NEAT_H
#define NEAT_H

#include <sys/types.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

//Maps directly to libuv contants
typedef enum {
    NEAT_RUN_DEFAULT = 0,
    NEAT_RUN_ONCE,
    NEAT_RUN_NOWAIT
} neat_run_mode;

struct neat_ctx; // global
struct neat_flow; // one per connection

struct neat_ctx *neat_init_ctx();
void neat_start_event_loop(struct neat_ctx *nc, neat_run_mode run_mode);
void neat_stop_event_loop(struct neat_ctx *nc);
int neat_get_backend_fd(struct neat_ctx *nc);
void neat_free_ctx(struct neat_ctx *nc);

typedef uint64_t neat_error_code;
struct neat_flow_operations;
typedef neat_error_code (*neat_flow_operations_fx)(struct neat_flow_operations *);

// Additional callbacks from D.1.2 sect. 3.2/3.3:
// Callback handler function prototypes
// Not including ctx/flow pointers, flow_ops struct has those as well
// as status code
//(struct neat_flow_operations *ops, int ecn, uint32_t rate)
typedef void (*neat_cb_flow_slowdown_t)(struct neat_flow_operations *, int, uint32_t);
//(struct neat_flow_operations *flowops, uint32_t new_rate)
typedef void (*neat_cb_flow_rate_hint_t)(struct neat_flow_operations *, uint32_t);
//struct neat_flow_operations *flowops, int context, const unsigned char *unsent
typedef void (*neat_cb_send_failure_t)(struct neat_flow_operations *, int, const unsigned char *);


struct neat_flow_operations
{
  void *userData;

  neat_error_code status;
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

// Flags to use for neat_flow_init()
#define NEAT_PRESERVE_MSG_BOUNDARIES (1 << 0)
#define NEAT_USE_SECURE_INTERFACE (1 << 1)

struct neat_flow_security {
    int security; // 1 = secure connection required, 2 = secure connection optional
    int verification; // 1 = required, 2 = optional
    const char* certificate; // filename for certificate
    const char* key; // filename for key
    const char** tls_versions; // list of tls versions available to use
    const char** ciphers; // list of ciphers available to use
};

struct neat_flow *neat_new_flow(struct neat_ctx *ctx);
neat_error_code neat_flow_init(struct neat_ctx *ctx, struct neat_flow* flow,
                                 uint64_t flags, int flow_profile, struct neat_flow_security *sec);
void neat_free_flow(struct neat_flow *flow);

neat_error_code neat_set_operations(struct neat_ctx *ctx, struct neat_flow *flow,
                                    struct neat_flow_operations *ops);

neat_error_code neat_open(struct neat_ctx *ctx, struct neat_flow *flow,
                          const char *name, uint16_t port);
neat_error_code neat_read(struct neat_ctx *ctx, struct neat_flow *flow,
                          unsigned char *buffer, uint32_t amt, uint32_t *actualAmt);
neat_error_code neat_write(struct neat_ctx *ctx, struct neat_flow *flow,
                           const unsigned char *buffer, uint32_t amt);
neat_error_code neat_write_ex(struct neat_ctx *ctx, struct neat_flow *flow,
                              const unsigned char *buffer, uint32_t amt,
                              int stream_id, int context, int pr_method, int pr_value,
                              const char* preferred_destination, int unordered,
                              float priority);
neat_error_code neat_get_property(struct neat_ctx *ctx, struct neat_flow *flow,
                                  uint64_t *outMask);
neat_error_code neat_set_property_json(struct neat_ctx *ctx, struct neat_flow *flow,
				  char *property_set);
neat_error_code neat_set_property(struct neat_ctx *ctx, struct neat_flow *flow,
                                  uint64_t inMask);
neat_error_code neat_accept(struct neat_ctx *ctx, struct neat_flow *flow,
                            const char *name, uint16_t port);
neat_error_code neat_shutdown(struct neat_ctx *ctx, struct neat_flow *flow);
neat_error_code neat_close(struct neat_ctx *ctx, struct neat_flow *flow);
neat_error_code neat_abort(struct neat_ctx *ctx, struct neat_flow *flow);
neat_error_code neat_change_timeout(struct neat_ctx *ctx, struct neat_flow *flow,
                                    int seconds);
neat_error_code neat_set_primary_dest(struct neat_ctx *ctx, struct neat_flow *flow,
                                      const char *name);
neat_error_code neat_request_capacity(struct neat_ctx *ctx, struct neat_flow *flow,
                                      int rate, int seconds);

// do we also need a set property with a void * or an int (e.g. timeouts) or should
// we create higher level named functions for such things?

// for property mask
#define NEAT_PROPERTY_OPTIONAL_SECURITY           (1 << 0)
#define NEAT_PROPERTY_REQUIRED_SECURITY           (1 << 1)
#define NEAT_PROPERTY_MESSAGE                     (1 << 2) // stream is default
#define NEAT_PROPERTY_IPV4_REQUIRED               (1 << 3)
#define NEAT_PROPERTY_IPV4_BANNED                 (1 << 4)
#define NEAT_PROPERTY_IPV6_REQUIRED               (1 << 5)
#define NEAT_PROPERTY_IPV6_BANNED                 (1 << 6)
#define NEAT_PROPERTY_SCTP_REQUIRED               (1 << 7)
#define NEAT_PROPERTY_SCTP_BANNED                 (1 << 8)
#define NEAT_PROPERTY_TCP_REQUIRED                (1 << 9)
#define NEAT_PROPERTY_TCP_BANNED                  (1 << 10)
#define NEAT_PROPERTY_UDP_REQUIRED                (1 << 11)
#define NEAT_PROPERTY_UDP_BANNED                  (1 << 12)
#define NEAT_PROPERTY_UDPLITE_REQUIRED            (1 << 13)
#define NEAT_PROPERTY_UDPLITE_BANNED              (1 << 14)
#define NEAT_PROPERTY_CONGESTION_CONTROL_REQUIRED (1 << 15)
#define NEAT_PROPERTY_CONGESTION_CONTROL_BANNED   (1 << 16)
#define NEAT_PROPERTY_RETRANSMISSIONS_REQUIRED    (1 << 17)
#define NEAT_PROPERTY_RETRANSMISSIONS_BANNED      (1 << 18)
#define NEAT_PROPERTY_SEAMLESS_HANDOVER_DESIRED   (1 << 19)
#define NEAT_PROPERTY_CONTINUOUS_CONNECTIVITY_DESIRED    (1 << 20)
#define NEAT_PROPERTY_DISABLE_DYNAMIC_ENHANCEMENT     (1 << 21)
#define NEAT_PROPERTY_LOW_LATENCY_DESIRED (1 << 22)

#define NEAT_ERROR_OK (0)
#define NEAT_OK NEAT_ERROR_OK
#define NEAT_ERROR_WOULD_BLOCK (1)
#define NEAT_ERROR_BAD_ARGUMENT (2)
#define NEAT_ERROR_IO (3)
#define NEAT_ERROR_DNS (4)
#define NEAT_ERROR_INTERNAL (5)
#define NEAT_ERROR_SECURITY (6)
#define NEAT_ERROR_UNABLE (7)
#define NEAT_ERROR_MESSAGE_TOO_BIG (8)
#define NEAT_ERROR_REMOTE (9)

// cleanup extern "C"
#ifdef __cplusplus
}
#endif
#endif // guard bars
