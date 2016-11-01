// this is the public API..

#ifndef NEAT_H
#define NEAT_H

#include <sys/types.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

// TODO: this __attribute__ feature supposedly works with both clang and
// modern gcc compilers. Could be moved to a cmake test for better
// portability.
#define NEAT_EXTERN __attribute__ ((__visibility__ ("default")))

//Maps directly to libuv contants
typedef enum {
    NEAT_RUN_DEFAULT = 0,
    NEAT_RUN_ONCE,
    NEAT_RUN_NOWAIT
} neat_run_mode;

struct neat_ctx; // global
struct neat_flow; // one per connection

NEAT_EXTERN struct neat_ctx *neat_init_ctx();
NEAT_EXTERN void neat_start_event_loop(struct neat_ctx *nc, neat_run_mode run_mode);
NEAT_EXTERN void neat_stop_event_loop(struct neat_ctx *nc);
NEAT_EXTERN int neat_get_backend_fd(struct neat_ctx *nc);
NEAT_EXTERN void neat_free_ctx(struct neat_ctx *nc);

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

enum neat_tlv_type {
    NEAT_TYPE_INTEGER = 0,
    NEAT_TYPE_FLOAT,
    NEAT_TYPE_STRING,
};
typedef enum neat_tlv_type neat_tlv_type;

enum neat_tlv_tag {
    NEAT_TAG_STREAM_ID = 0,
    NEAT_TAG_STREAM_COUNT,
    NEAT_TAG_LOCAL_NAME,
    NEAT_TAG_SERVICE_NAME,
    NEAT_TAG_CONTEXT,
    NEAT_TAG_PARTIAL_RELIABILITY_METHOD,
    NEAT_TAG_PARTIAL_RELIABILITY_VALUE,
    NEAT_TAG_PARTIAL_MESSAGE_RECEIVED,
    NEAT_TAG_PARTIAL_SEQNUM,
    NEAT_TAG_UNORDERED,
    NEAT_TAG_UNORDERED_SEQNUM,
    NEAT_TAG_DESTINATION_IP_ADDRESS,
    NEAT_TAG_PRIORITY,
    NEAT_TAG_FLOW_GROUP,
    NEAT_TAG_CC_ALGORITHM,

    NEAT_TAG_LAST
};
typedef enum neat_tlv_tag neat_tlv_tag;

struct neat_tlv {
    neat_tlv_tag  tag;
    neat_tlv_type type;

    union {
        int   integer;
        char *string;
        float real;
    } value;
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

NEAT_EXTERN struct neat_flow *neat_new_flow(struct neat_ctx *ctx);

NEAT_EXTERN neat_error_code neat_set_operations(struct neat_ctx *ctx, struct neat_flow *flow,
                                    struct neat_flow_operations *ops);

NEAT_EXTERN neat_error_code neat_get_stats(struct neat_ctx *ctx, char **neat_stats);

NEAT_EXTERN neat_error_code neat_open(struct neat_ctx *mgr, struct neat_flow *flow,
                          const char *name, uint16_t port,
                          struct neat_tlv optional[], unsigned int opt_count);
NEAT_EXTERN neat_error_code neat_read(struct neat_ctx *ctx, struct neat_flow *flow,
                          unsigned char *buffer, uint32_t amt, uint32_t *actualAmt,
                          struct neat_tlv optional[], unsigned int opt_count);
NEAT_EXTERN neat_error_code neat_write(struct neat_ctx *ctx, struct neat_flow *flow,
                           const unsigned char *buffer, uint32_t amt,
                           struct neat_tlv optional[], unsigned int opt_count);
NEAT_EXTERN neat_error_code neat_get_property(struct neat_ctx *ctx, struct neat_flow *flow,
                                              const char* name, void *ptr, size_t *size);
NEAT_EXTERN neat_error_code neat_set_property(struct neat_ctx *ctx, struct neat_flow *flow,
                                              const char* properties);
NEAT_EXTERN neat_error_code neat_accept(struct neat_ctx *ctx, struct neat_flow *flow,
                            uint16_t port, struct neat_tlv optional[], unsigned int opt_count);
NEAT_EXTERN neat_error_code neat_shutdown(struct neat_ctx *ctx, struct neat_flow *flow);
NEAT_EXTERN neat_error_code neat_close(struct neat_ctx *ctx, struct neat_flow *flow);
NEAT_EXTERN neat_error_code neat_abort(struct neat_ctx *ctx, struct neat_flow *flow);
NEAT_EXTERN neat_error_code neat_change_timeout(struct neat_ctx *ctx, struct neat_flow *flow,
                                    unsigned int seconds);
NEAT_EXTERN neat_error_code neat_set_primary_dest(struct neat_ctx *ctx, struct neat_flow *flow,
                                      const char *name);
NEAT_EXTERN neat_error_code neat_request_capacity(struct neat_ctx *ctx, struct neat_flow *flow,
                                      int rate, int seconds);
NEAT_EXTERN neat_error_code neat_set_checksum_coverage(struct neat_ctx *ctx, struct neat_flow *flow,
                                      unsigned int send_coverage, unsigned int receive_coverage);
// The filename should be a PEM file with both cert and key
NEAT_EXTERN neat_error_code neat_secure_identity(struct neat_ctx *ctx, struct neat_flow *flow,
                                     const char *filename);

NEAT_EXTERN neat_error_code neat_set_qos(struct neat_ctx *ctx,
					struct neat_flow *flow, uint8_t qos);
NEAT_EXTERN neat_error_code neat_set_ecn(struct neat_ctx *ctx,
					struct neat_flow *flow, uint8_t ecn);

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
#define NEAT_ERROR_OUT_OF_MEMORY (10)

#define NEAT_INVALID_STREAM (-1)

#define NEAT_OPTARGS (__optional_arguments)
#define NEAT_OPTARGS_COUNT (__optional_argument_count)

#define NEAT_OPTARGS_MAX (NEAT_TAG_LAST)

#define NEAT_OPTARGS_INIT() \
    do { \
        NEAT_OPTARGS_COUNT = 0; \
    } while (0);

#define NEAT_OPTARGS_RESET NEAT_OPTARGS_INIT

#ifdef assert

#define NEAT_OPTARGS_DECLARE(max) \
    struct neat_tlv __optargs_buffer[max]; \
    struct neat_tlv *NEAT_OPTARGS = &__optargs_buffer[0]; \
    unsigned int NEAT_OPTARGS_COUNT; \
    unsigned int __optional_arguments_limit = max;

#define NEAT_OPTARG_INT(tagname, val) \
    do { \
        assert(NEAT_OPTARGS_COUNT < __optional_arguments_limit);\
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].value.integer = val;\
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].type = NEAT_TYPE_INTEGER;\
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].tag = tagname;\
        NEAT_OPTARGS_COUNT++;\
    } while (0);

#define NEAT_OPTARG_FLOAT(tagname, val) \
    do { \
        assert(NEAT_OPTARGS_COUNT < __optional_arguments_limit);\
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].value.real = val;\
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].type = NEAT_TYPE_FLOAT;\
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].tag = tagname;\
        NEAT_OPTARGS_COUNT++;\
    } while (0);

#define NEAT_OPTARG_STRING(tagname, val) \
    do { \
        assert(NEAT_OPTARGS_COUNT < __optional_arguments_limit);\
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].value.string = val;\
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].type = NEAT_TYPE_STRING;\
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].tag = tagname;\
        NEAT_OPTARGS_COUNT++;\
    } while (0);

#else

#define NEAT_OPTARGS_DECLARE(max) \
    struct neat_tlv __optargs_buffer[max]; \
    struct neat_tlv *NEAT_OPTARGS = &__optargs_buffer[0]; \
    unsigned int NEAT_OPTARGS_COUNT;

#define NEAT_OPTARG_INT(tagname, val) \
    do { \
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].value.integer = val;\
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].type = NEAT_TYPE_INTEGER;\
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].tag = tagname;\
        NEAT_OPTARGS_COUNT++;\
    } while (0);

#define NEAT_OPTARG_FLOAT(tagname, val) \
    do { \
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].value.real = val;\
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].type = NEAT_TYPE_FLOAT;\
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].tag = tagname;\
        NEAT_OPTARGS_COUNT++;\
    } while (0);

#define NEAT_OPTARG_STRING(tagname, val) \
    do { \
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].value.string = val;\
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].type = NEAT_TYPE_STRING;\
        NEAT_OPTARGS[NEAT_OPTARGS_COUNT].tag = tagname;\
        NEAT_OPTARGS_COUNT++;\
    } while (0);

#endif // ifdef assert else


// cleanup extern "C"
#ifdef __cplusplus
}
#endif
#endif // guard bars
