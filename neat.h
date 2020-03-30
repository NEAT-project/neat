#ifndef NEAT_H
#define NEAT_H

// Avoid additional includes for SWIG
#ifndef SWIG
#include <sys/types.h>
#include <netinet/in.h>
#include <uv.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// TODO: this __attribute__ feature supposedly works with both clang and
// modern gcc compilers. Could be moved to a cmake test for better
// portability.
#ifndef SWIG
#define NEAT_EXTERN __attribute__ ((__visibility__ ("default")))
#else
// SWIG doesnt like the above definition
#define NEAT_EXTERN extern
#endif

//Maps directly to libuv contants
typedef enum {
    NEAT_RUN_DEFAULT = 0,
    NEAT_RUN_ONCE,
    NEAT_RUN_NOWAIT
} neat_run_mode;

struct neat_ctx;    // global
struct neat_flow;   // one per connection

typedef uint64_t neat_error_code;

NEAT_EXTERN int neat_get_socket_fd(struct neat_flow *nf);

NEAT_EXTERN struct neat_ctx *neat_init_ctx();
NEAT_EXTERN neat_error_code neat_start_event_loop(struct neat_ctx *nc, neat_run_mode run_mode);
NEAT_EXTERN uv_loop_t *neat_get_event_loop(struct neat_ctx *ctx);
NEAT_EXTERN void neat_stop_event_loop(struct neat_ctx *nc);
NEAT_EXTERN int neat_get_backend_fd(struct neat_ctx *nc);
NEAT_EXTERN int neat_get_backend_timeout(struct neat_ctx *nc);
NEAT_EXTERN void neat_free_ctx(struct neat_ctx *nc);
NEAT_EXTERN void neat_log_level(struct neat_ctx *ctx, uint8_t level);
NEAT_EXTERN uint8_t neat_log_file(struct neat_ctx *ctx, const char* file_name);

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


struct neat_flow_operations {
    void *userData;

    neat_error_code status;
    uint16_t stream_id;
    int transport_protocol;
    neat_flow_operations_fx on_connected;
    neat_flow_operations_fx on_error;
    neat_flow_operations_fx on_readable;
    neat_flow_operations_fx on_writable;
    neat_flow_operations_fx on_all_written;
    neat_flow_operations_fx on_network_status_changed;
    neat_flow_operations_fx on_aborted;
    neat_flow_operations_fx on_timeout;
    neat_flow_operations_fx on_close;
    neat_flow_operations_fx on_parameters;
    neat_cb_send_failure_t on_send_failure;
    neat_cb_flow_slowdown_t on_slowdown;
    neat_cb_flow_rate_hint_t on_rate_hint;
    char *label;

    struct neat_ctx *ctx;
    struct neat_flow *flow;
};

NEAT_EXTERN void set_ops_user_data(struct neat_flow_operations *ops, unsigned char* data);
NEAT_EXTERN unsigned char* get_ops_user_data(struct neat_flow_operations *ops);


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
    NEAT_TAG_LOCAL_ADDRESS,
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
    NEAT_TAG_TRANSPORT_STACK,
    NEAT_TAG_CHANNEL_NAME,

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

NEAT_EXTERN struct neat_flow *neat_new_flow(struct neat_ctx *ctx);

NEAT_EXTERN neat_error_code neat_set_operations(struct neat_ctx *ctx,
                                                struct neat_flow *flow,
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
NEAT_EXTERN int neat_getlpaddrs(struct neat_ctx *ctx, struct neat_flow *flow, struct sockaddr** addrs, const int local);
NEAT_EXTERN void neat_freelpaddrs(struct sockaddr* addrs);
NEAT_EXTERN neat_error_code neat_change_timeout(struct neat_ctx *ctx, struct neat_flow *flow,
                                    unsigned int seconds);
NEAT_EXTERN neat_error_code neat_set_primary_dest(struct neat_ctx *ctx, struct neat_flow *flow,
                                      const char *name);
NEAT_EXTERN neat_error_code neat_set_checksum_coverage(struct neat_ctx *ctx, struct neat_flow *flow,
                                      unsigned int send_coverage, unsigned int receive_coverage);
// The filename should be a PEM file with both cert and key
NEAT_EXTERN neat_error_code neat_secure_identity(struct neat_ctx *ctx, struct neat_flow *flow,
                                     const char *filename, int pemType);
NEAT_EXTERN neat_error_code neat_set_qos(struct neat_ctx *ctx,
                    struct neat_flow *flow, uint8_t qos);
NEAT_EXTERN int neat_get_qos(struct neat_ctx *ctx, struct neat_flow *flow);
NEAT_EXTERN neat_error_code neat_set_ecn(struct neat_ctx *ctx,
                    struct neat_flow *flow, uint8_t ecn);
NEAT_EXTERN neat_error_code neat_set_low_watermark(struct neat_ctx *ctx, struct neat_flow *flow, uint32_t watermark);
#if defined(WEBRTC_SUPPORT)
NEAT_EXTERN neat_error_code neat_send_remote_parameters(struct neat_ctx *ctx, struct neat_flow *flow, char* params);
#endif

#define NEAT_ERROR_OK               (0)
#define NEAT_OK                     NEAT_ERROR_OK
#define NEAT_ERROR_WOULD_BLOCK      (1)
#define NEAT_ERROR_BAD_ARGUMENT     (2)
#define NEAT_ERROR_IO               (3)
#define NEAT_ERROR_DNS              (4)
#define NEAT_ERROR_INTERNAL         (5)
#define NEAT_ERROR_SECURITY         (6)
#define NEAT_ERROR_UNABLE           (7)
#define NEAT_ERROR_MESSAGE_TOO_BIG  (8)
#define NEAT_ERROR_REMOTE           (9)
#define NEAT_ERROR_OUT_OF_MEMORY    (10)

#define NEAT_INVALID_STREAM         (-1)

#define NEAT_LOG_OFF                (0)
#define NEAT_LOG_ERROR              (1)
#define NEAT_LOG_WARNING            (2)
#define NEAT_LOG_INFO               (3)
#define NEAT_LOG_DEBUG              (4)

#define NEAT_OPTARGS                (__optional_arguments)
#define NEAT_OPTARGS_COUNT          (__optional_argument_count)

#define NEAT_OPTARGS_MAX            (NEAT_TAG_LAST)

#define NEAT_OPTARGS_INIT() \
    do { \
        NEAT_OPTARGS_COUNT = 0; \
    } while (0);

#define NEAT_OPTARGS_RESET          NEAT_OPTARGS_INIT

#define NEAT_CERT_NONE   0
#define NEAT_CERT_PEM    1
#define NEAT_KEY_PEM     2
#define NEAT_CERT_KEY_PEM 3

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

typedef enum {
    NEAT_STACK_UDP = 1,
    NEAT_STACK_UDPLITE,
    NEAT_STACK_TCP,
    NEAT_STACK_MPTCP,
    NEAT_STACK_SCTP,
    NEAT_STACK_SCTP_UDP,
    NEAT_STACK_WEBRTC
} neat_protocol_stack_type;


// cleanup extern "C"
#ifdef __cplusplus
}
#endif
#endif // guard bars
