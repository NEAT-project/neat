#ifndef NEAT_INTERNAL_H
#define NEAT_INTERNAL_H

#include <stdint.h>
#include <uv.h>
#include <jansson.h>

#include "neat.h"
#include "neat_queue.h"
#include "neat_security.h"
#include "neat_pm_socket.h"

#ifdef WEBRTC_SUPPORT
#include "neat_webrtc_tools.h"
#endif

#ifdef __linux__
    #include "neat_linux.h"
#endif //  __linux__

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
    #include "neat_bsd.h"
#endif // defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)

#ifdef USRSCTP_SUPPORT
    #include "neat_usrsctp.h"
    #include <usrsctp.h>

    struct usr_internal {
        uint16_t num_ctx;
        int s4_fd;
        int us4_fd;
        int s6_fd;
        int us6_fd;
    } usr_intern;
#else // USRSCTP_SUPPORT
    #define NEAT_INTERNAL_USRSCTP
#endif // USRSCTP_SUPPORT

#define _unused(x) ((void)(x))

#ifdef MPTCP_SUPPORT
    #define MPTCP_SYS_DISABLED (0) // MPTCP is disabled globaly on the system or not installed
    #define MPTCP_SYS_ENABLED (1) // MPTCP is enabled globaly on the system
    #define MPTCP_SYS_APP_CTRL (2) // MPTCP is controlled by the application
                               // via MPTCP_ENABLED (value 42) socket option
    #define NEAT_INTERNAL_MPTCP \
        int sys_mptcp_enabled;
#else // MPTCP_SUPPORT
    #define NEAT_INTERNAL_MPTCP
#endif // MPTCP_SUPPORT

#include "neat_log.h"
#include "neat_stat.h"

#define NEAT_INTERNAL_CTX \
    void (*cleanup)(struct neat_ctx *nc); \
    struct neat_src_addrs src_addrs; \
    struct neat_event_cbs* event_cbs; \
    uint8_t src_addr_cnt; \
    uint8_t src_addr_dump_done; \
    uint16_t __pad

#define NEAT_MAX_NUM_PROTO  5
#define MAX_LOCAL_ADDR      64

struct neat_event_cb;
struct neat_addr;
struct neat_resolver;
struct neat_pvd;

//TODO: One drawback with using LIST from queue.h, is that a callback can only
//be member of one list. Decide if this is critical and improve if needed
LIST_HEAD(neat_event_cbs, neat_event_cb);
LIST_HEAD(neat_src_addrs, neat_addr);

struct neat_pib
{ // TODO
    uint8_t dummy;
};

struct neat_cib
{ // TODO
    uint8_t dummy;
};

LIST_HEAD(neat_flow_list_head, neat_flow);

struct neat_ctx
{
    uv_loop_t *loop;
    struct neat_resolver *resolver;
    struct neat_pib pib;
    struct neat_cib cib;
    struct neat_flow_list_head flows;
    uv_timer_t addr_lifetime_handle;

    // PvD
    struct neat_pvd* pvd;

    neat_error_code error;

    /* logging members */
    uint8_t log_level;
    uint8_t color_supported;
    struct timeval tv_init;
    FILE *neat_log_fd;

    // resolver
    NEAT_INTERNAL_CTX;
    NEAT_INTERNAL_OS;
    NEAT_INTERNAL_USRSCTP
    NEAT_INTERNAL_MPTCP
};

void nt_ctx_fail_on_error(struct neat_ctx *nc, neat_error_code error);

struct neat_he_candidate;
struct neat_pollable_socket;

typedef struct neat_ctx neat_ctx;
typedef neat_error_code (*neat_read_impl)(struct neat_ctx *ctx, struct neat_flow *flow,
                                          unsigned char *buffer, uint32_t amt, uint32_t *actualAmt,
                                          struct neat_tlv optional[], unsigned int opt_count);
typedef neat_error_code (*neat_write_impl)(struct neat_ctx *ctx, struct neat_flow *flow,
                                           const unsigned char *buffer, uint32_t amt, struct neat_tlv optional[], unsigned int opt_count);
typedef int (*neat_accept_impl)(struct neat_ctx *ctx, struct neat_flow *flow, int fd);
#if defined(USRSCTP_SUPPORT)
typedef struct socket * (*neat_accept_usrsctp_impl)(struct neat_ctx *ctx, struct neat_flow *flow, struct neat_pollable_socket *listen_socket);
#endif
typedef int (*neat_connect_impl)(struct neat_he_candidate *candidate, uv_poll_cb callback_fx);
typedef int (*neat_listen_impl)(struct neat_ctx *ctx, struct neat_flow *flow);
typedef int (*neat_close_impl)(struct neat_ctx *ctx, struct neat_flow *flow);
typedef int (*neat_close2_impl)(int fd);
typedef int (*neat_shutdown_impl)(struct neat_ctx *ctx, struct neat_flow *flow);
#if defined(USRSCTP_SUPPORT)
typedef int (*neat_usrsctp_receive_cb)(struct socket *sock, union sctp_sockstore addr, void *data,
                                 size_t datalen, struct sctp_rcvinfo, int flags, void *ulp_info);
typedef int (*neat_usrsctp_send_cb)(struct socket *sock, uint32_t free, void *ulp_info);
#endif

struct neat_buffered_message {
    unsigned char *buffered; // memory for write buffers
    size_t bufferedOffset;  // offset of data still to be written
    size_t bufferedSize;    // amount of unwritten data
    size_t bufferedAllocation; // size of buffered allocation
    uint16_t stream_id;
    uint8_t unordered;
    uint8_t pr_method;
    uint32_t pr_value;
    TAILQ_ENTRY(neat_buffered_message) message_next;
};

#ifdef SCTP_MULTISTREAMING
struct neat_read_queue_message {
    unsigned char *buffer;
    size_t buffer_size;
    TAILQ_ENTRY(neat_read_queue_message) message_next;
};
#endif

typedef enum {
    NEAT_FLOW_CLOSED = 1,
    NEAT_FLOW_CONNECTING,
    NEAT_FLOW_OPEN,
    NEAT_FLOW_CLOSING,
    NEAT_FLOW_WAITING
} neat_flow_states;

#define NEAT_STACK_MAX_NUM              6
#define SCTP_UDP_TUNNELING_PORT         9899
#define SCTP_ADAPTATION_NEAT            1207
#define SCTP_STREAMCOUNT                123

TAILQ_HEAD(neat_message_queue_head, neat_buffered_message);
TAILQ_HEAD(neat_read_queue_head, neat_read_queue_message);

struct neat_iofilter;
typedef neat_error_code (*neat_filter_write_impl)(struct neat_ctx *ctx, struct neat_flow *flow,
                                                  struct neat_iofilter *filter,
                                                  const unsigned char *buffer, uint32_t amt,
                                                  struct neat_tlv optional[], unsigned int opt_count);
typedef neat_error_code (*neat_filter_read_impl)(struct neat_ctx *ctx, struct neat_flow *flow,
                                                 struct neat_iofilter *filter,
                                                 unsigned char *buffer, uint32_t amt, uint32_t *actualAmt,
                                                 struct neat_tlv optional[], unsigned int opt_count);

struct neat_iofilter
{
    void *userData;
    void (*dtor)(struct neat_iofilter *);
    struct neat_iofilter *next;

    neat_filter_write_impl writefx;
    neat_filter_read_impl  readfx;
};

#define CIPHER_BUFFER_SIZE 8192

#if defined(NEAT_SCTP_DTLS) || defined(NEAT_USETLS)
struct security_data
{
    SSL_CTX *ctx;
    SSL *ssl;

    BIO *outputBIO;
    int outCipherBufferUsed;
    unsigned char outCipherBuffer[CIPHER_BUFFER_SIZE];

    BIO *inputBIO;
    int inCipherBufferUsed;
    int inCipherBufferSent;
    unsigned char inCipherBuffer[CIPHER_BUFFER_SIZE];

    BIO *dtlsBIO;

    neat_flow_operations_fx pushed_on_connected;
    neat_flow_operations_fx pushed_on_readable;
    neat_flow_operations_fx pushed_on_writable;
    uint8_t state;
};
#endif

struct neat_dtls_data
{
    void *userData;

    void (*dtor)(struct neat_dtls_data *);
};

struct neat_pollable_socket
{
    struct neat_flow    *flow;

#if defined(USRSCTP_SUPPORT) || defined(WEBRTC_SUPPORT)
    struct socket *usrsctp_socket;
#endif

    int          fd;
    uint8_t      family;
    int          type;
    int          stack;
    unsigned int port;

    char                    *dst_address;
    struct sockaddr_storage dst_sockaddr;
    socklen_t               dst_len;

    char                    *src_address;
    struct sockaddr_storage src_sockaddr;
    socklen_t               src_len;

    struct sockaddr_storage local_addr[MAX_LOCAL_ADDR];
    unsigned int nr_local_addr;

    size_t      write_limit;        // maximum to write if the socket supports partial writes
    size_t      write_size;         // send buffer size
    size_t      read_size;          // receive buffer size

    uint8_t                     multistream;            // multistreaming active
    uint8_t                     is_closed;

    unsigned int                sctp_explicit_eor : 1;
    unsigned int                sctp_partial_reliability : 1;
    uint16_t                    sctp_streams_available; // available streams
#ifdef SCTP_MULTISTREAMING
    uint8_t                     sctp_notification_wait; // wait for all notifications
    uint8_t                     sctp_notification_recvd;// we have received a notification
    uint8_t                     sctp_stream_reset;      // peer supports stream reset
    uint8_t                     sctp_neat_peer;         // peer supports neat
    uint16_t                    sctp_streams_used;      // used streams
    struct neat_flow_list_head  sctp_multistream_flows; // multistream flows
#endif

    struct neat_pollable_socket *listen_socket;

    struct neat_dtls_data *dtls_data;

    uv_poll_t *handle;

    TAILQ_ENTRY(neat_pollable_socket) next;
};

struct neat_flow
{
    // Main socket used for communication, not listening
    uint8_t state;
    struct neat_pollable_socket *socket;
    TAILQ_HEAD(neat_listen_socket_head, neat_pollable_socket) listen_sockets;
    struct neat_flow_operations operations;
    const char *name;
    char *server_pem;
    char *cert_pem;
    char *key_pem;
    uint16_t port;
    uint8_t qos;
    uint8_t ecn;
    struct neat_resolver_results *resolver_results;
    const struct sockaddr *sockAddr; // raw unowned pointer into resolver_results
    struct neat_ctx *ctx; // raw convenience pointer
    struct neat_iofilter *iofilters;
    uv_timer_t *initiate_timer;

    uint32_t group;
    float priority;

    const char *cc_algorithm;

    struct neat_message_queue_head bufferedMessages;
    struct neat_flow_statistics flow_stats;

    // The memory buffer for reading. Used of SCTP reassembly.
    unsigned char   *readBuffer;            // memory for read buffer
    size_t          readBufferSize;         // amount of received data
    size_t          readBufferAllocation;   // size of buffered allocation
    int             readBufferMsgComplete;  // it contains a complete user message

    json_t *properties;
    json_t *user_ips;

    neat_read_impl      readfx;
    neat_write_impl     writefx;
    neat_accept_impl    acceptfx;
    neat_connect_impl   connectfx;
    neat_close_impl     closefx;
    neat_shutdown_impl  shutdownfx;

    uint8_t heConnectAttemptCount;


#if defined(USRSCTP_SUPPORT)
    neat_accept_usrsctp_impl acceptusrsctpfx;
#endif

    unsigned int hefirstConnect             : 1;
    unsigned int firstWritePending          : 1;
    unsigned int acceptPending              : 1;
    unsigned int isPolling                  : 1;
    unsigned int everConnected              : 1;
    unsigned int isDraining                 : 1;
    unsigned int isServer                   : 1; // i.e. created via accept()
    unsigned int isMultihoming              : 1;
    unsigned int security_needed            : 1;
    unsigned int isSCTPIdata                : 1;
    unsigned int isClosing                  : 1;
    unsigned int notifyDrainPending         : 1;
    unsigned int preserveMessageBoundaries  : 1;
    unsigned int eofSeen                    : 1;
    unsigned int skipCertVerification       : 1;
    unsigned int webrtcEnabled              : 1;
    unsigned int tproxy                     : 1; // is transparent proxy socket

    unsigned int streams_requested;

    struct neat_he_candidates *candidate_list;

    uv_poll_cb callback_fx;

    LIST_ENTRY(neat_flow) next_flow;

#ifdef SCTP_MULTISTREAMING
    unsigned int                    multistream_check       : 1;
    unsigned int                    multistream_shutdown    : 1;
    unsigned int                    multistream_reset_in    : 1;
    unsigned int                    multistream_reset_out   : 1;

    uv_timer_t                      *multistream_timer;
    uint16_t                        multistream_id;
    LIST_ENTRY(neat_flow)           multistream_next_flow;

    struct neat_read_queue_head     multistream_read_queue;
    size_t                          multistream_read_queue_size;

    //neat_flow_states                multistream_state;
#endif // SCTP_MULTISTREAMING
    // WebRTC
    uint8_t role; //just temporary
    struct peer_connection *peer_connection;
};

typedef struct neat_flow neat_flow;

struct neat_path_stats {
    void* ignored;
};

typedef struct neat_path_stats neat_path_stats;

struct neat_interface_stats {
    void* ignored;
};

typedef struct neat_interface_stats neat_interface_stats;

//NEAT resolver public data structures/functions
struct neat_resolver_res;
struct neat_resolver_server;

LIST_HEAD(neat_resolver_results, neat_resolver_res);
LIST_HEAD(neat_resolver_servers, neat_resolver_server);

//Arguments are result struct (must be freed by user), neat_resolver_code and
//user_data passed to getaddrinfo
typedef neat_error_code (*neat_resolver_handle_t)(struct neat_resolver_results *,
                                                  uint8_t,
                                                  void *);
typedef void (*neat_resolver_cleanup_t)(struct neat_resolver *resolver);

enum neat_resolver_code {
    //Everything is good
    NEAT_RESOLVER_OK = 0,
    //Resolving timed out without result
    NEAT_RESOLVER_TIMEOUT,
    //Signal internal error
    NEAT_RESOLVER_ERROR,
};

enum neat_resolver_mark {
    //Set for our well-known global servers
    NEAT_RESOLVER_SERVER_STATIC = 0,
    //Indicate that this server should be deleted (i.e., it is removed from
    //resolv.conf)
    NEAT_RESOLVER_SERVER_DELETE,
    //Indicate that this server should be kept
    NEAT_RESOLVER_SERVER_ACTIVE
};

struct neat_resolver_server {
    struct sockaddr_storage server_addr;
    uint8_t mark;
    LIST_ENTRY(neat_resolver_server) next_server;
};

//Struct passed to resolver callback, mirrors what we get back from getaddrinfo
struct neat_resolver_res {
    int32_t ai_family;
    uint32_t if_idx;
    struct sockaddr_storage src_addr;
    socklen_t src_addr_len;
    struct sockaddr_storage dst_addr;
    socklen_t dst_addr_len;
    uint8_t internal;
    LIST_ENTRY(neat_resolver_res) next_res;
};

enum neat_sockopt_type {
    NEAT_SOCKOPT_INT = 0,
    NEAT_SOCKOPT_STRING,
};

struct neat_he_sockopt {
    uint32_t level;
    uint32_t name;
    enum neat_sockopt_type type;
    union {
        int i_val;
        char *s_val;
    } value;
    TAILQ_ENTRY(neat_he_sockopt) next;
};

TAILQ_HEAD(sock_opts_head, neat_he_sockopt);

// Linked list passed to HE after the first PM call.
// The list contains each candidate HE should get resolved.
struct neat_he_candidate {
    struct neat_pollable_socket *pollable_socket;
    uv_timer_t *prio_timer;
    uv_poll_cb callback_fx;
    uint32_t if_idx;
    char *if_name;
    int32_t priority;
    json_t *properties;
    struct neat_ctx *ctx;
    struct sock_opts_head sock_opts;
    uint8_t to_be_removed;
    TAILQ_ENTRY(neat_he_candidate) next;
    TAILQ_ENTRY(neat_he_candidate) resolution_list;
};

TAILQ_HEAD(neat_he_candidates, neat_he_candidate);

// Connection attempt result sent by HE to PM.
struct cib_he_res {
    char *interface;
    char *remote_ip;
    unsigned int remote_port;
    int transport;
};

void nt_free_candidates(struct neat_ctx *ctx, struct neat_he_candidates *candidates);
void nt_free_candidate(struct neat_ctx *ctx, struct neat_he_candidate *candidate);

// Connect context needed during HE.
struct he_cb_ctx {
    uv_poll_t *handle;
    struct neat_ctx *nc;
    struct neat_resolver_res *candidate;
    neat_flow *flow;
#if defined(USRSCTP_SUPPORT)
    struct socket *sock;
#endif
    int fd;
    int32_t ai_socktype;
    int32_t ai_stack;

    LIST_ENTRY(he_cb_ctx) next_he_ctx;
};

//Intilize resolver. Sets up internal callbacks etc.
//Resolve is required, cleanup is not
struct neat_resolver *nt_resolver_init(struct neat_ctx *nc,
                                         const char *resolv_conf_path);

//Release all memory occupied by a resolver. Resolver can't be used again
void nt_resolver_release(struct neat_resolver *resolver);

//Free the list of results
void nt_resolver_free_results(struct neat_resolver_results *results);

struct neat_pollable_socket *nt_find_multistream_socket(neat_ctx *ctx, neat_flow *new_flow);
uint8_t nt_wait_for_multistream_socket(neat_ctx *ctx, neat_flow *new_flow);

//Start to resolve a domain name (or literal). Accepts a list of protocols, will
//set socktype based on protocol
uint8_t nt_resolve(struct neat_resolver *resolver,
                         uint8_t family,
                         const char *node,
                         uint16_t port,
                         neat_resolver_handle_t handle_resolve,
                         void *user_data);

//Update timeouts (in ms) for DNS resolving. T1 is total timeout, T2 is how long
//to wait after first reply from DNS server. Initial values are 30s and 1s.
void nt_resolver_update_timeouts(struct neat_resolver *resolver, uint16_t t1,
        uint16_t t2);

void nt_io_error(neat_ctx *ctx, neat_flow *flow, neat_error_code code);

struct neat_iofilter *insert_neat_iofilter(neat_ctx *ctx, neat_flow *flow);

//Initialize PvD
struct neat_pvd *nt_pvd_init(struct neat_ctx *nc);

//Free PvD resources
void neat_pvd_release(struct neat_pvd *pvd);

enum neat_events{
    //A new address has been added to an interface
    NEAT_NEWADDR = 0,
    //An address has been updated (typically ifa_pref or ifa_valid)
    NEAT_UPDATEADDR,
    //An address has been deleted from an interface
    NEAT_DELADDR,
    __NEAT_MAX_EVENT
};
#define NEAT_MAX_EVENT (__NEAT_MAX_EVENT - 1)

//Register/remove a callback from the NEAT callback API
uint8_t nt_add_event_cb(struct neat_ctx *nc, uint8_t event_type,
        struct neat_event_cb *cb);
uint8_t nt_remove_event_cb(struct neat_ctx *nc, uint8_t event_type,
        struct neat_event_cb *cb);

struct neat_resolver_src_dst_addr;
LIST_HEAD(neat_resolver_pairs, neat_resolver_src_dst_addr);
#define MAX_DOMAIN_LENGTH   254

//This data structure must be filled out and added using neat_add_event_cb in
//order for an application to register for a callback
//TODO: Fix forward declaration error, so that this can be placed with the rest
//of the callback stuff
struct neat_event_cb {
    //So far we only support one type of callback. p_ptr is data in this
    //cb-struct, data is decided by callback type
    int (*event_cb)(struct neat_ctx *nc, void *p_ptr, void *data);
    void *data;
    LIST_ENTRY(neat_event_cb) next_cb;
};

neat_error_code neat_he_lookup(neat_ctx *ctx, neat_flow *flow, uv_poll_cb callback_fx);
neat_error_code nt_he_open(neat_ctx *ctx, neat_flow *flow, struct neat_he_candidates *candidate_list, uv_poll_cb callback_fx);

// Internal routines for hooking up lower-level services/modules with
// API callbacks:
void nt_notify_cc_congestion(neat_flow *flow, int ecn, uint32_t rate);
void nt_notify_cc_hint(neat_flow *flow, int ecn, uint32_t rate);
void nt_notify_send_failure(neat_flow *flow, neat_error_code code, int context, const unsigned char *unsent_buffer);
void nt_notify_timeout(neat_flow *flow);
void nt_notify_aborted(neat_flow *flow);
void nt_notify_close(neat_flow *flow);
void nt_notify_network_status_changed(neat_flow *flow, neat_error_code code);

int nt_base_stack(neat_protocol_stack_type stack);
int nt_stack_to_protocol(neat_protocol_stack_type stack);

extern const char *neat_tag_name[NEAT_TAG_LAST];

#define HANDLE_OPTIONAL_ARGUMENTS_START() \
    do {\
        if (optional != NULL && opt_count > 0) {\
            for (unsigned int i = 0; i < opt_count; ++i) {\
                switch (optional[i].tag) {

#define OPTIONAL_ARGUMENT(tag, var, field, vartype, typestr)\
    case tag:\
             if (optional[i].type != vartype)\
        nt_log(ctx, NEAT_LOG_DEBUG,\
                 "Optional argument \"%s\" passed to function %s: "\
                 "Expected type %s, specified as something else. "\
                 "Ignoring.", #tag, __func__, #typestr);\
             else\
        var = optional[i].value.field ;\
        break;

#define OPTIONAL_INTEGER(tag, var)\
        OPTIONAL_ARGUMENT(tag, var, integer, NEAT_TYPE_INTEGER, "integer")

#define OPTIONAL_STRING(tag, var)\
        OPTIONAL_ARGUMENT(tag, var, string, NEAT_TYPE_STRING, "string")

#define OPTIONAL_FLOAT(tag, var)\
        OPTIONAL_ARGUMENT(tag, var, real, NEAT_TYPE_FLOAT, "float")

#define SKIP_OPTARG(tag)\
    case tag:\
        break;

/* Like OPTIONAL_ARGUMENT, but sets the value in the presence parameter to 1 if
 * the optional argument is present. Make sure to initialize the variable to 0;
 */
#define OPTIONAL_ARGUMENT_PRESENT(tag, var, field, presence, vartype, typestr)\
    case tag:\
        if (optional[i].type != vartype) {\
            nt_log(ctx, NEAT_LOG_DEBUG,\
                     "Optional argument \"%s\" passed to function %s: "\
                     "Expected type %s, specified as something else. "\
                     "Ignoring.", "stream", #tag, __func__, typestr);\
        } else {\
            var = optional[i].value.field ;\
            presence = 1;\
        }\
        break;

#define OPTIONAL_INTEGER_PRESENT(tag, var, presence)\
        OPTIONAL_ARGUMENT_PRESENT(tag, var, integer, presence, NEAT_TYPE_INTEGER, "integer")

#define OPTIONAL_STRING_PRESENT(tag, var, presence)\
        OPTIONAL_ARGUMENT_PRESENT(tag, var, string, presence, NEAT_TYPE_STRING, "string")

#define OPTIONAL_FLOAT_PRESENT(tag, var, presence)\
        OPTIONAL_ARGUMENT_PRESENT(tag, var, real, presence, NEAT_TYPE_FLOAT, "float")

#define HANDLE_OPTIONAL_ARGUMENTS_END() \
                default:\
                    nt_log(ctx, NEAT_LOG_DEBUG,\
                             "Unexpected optional argument \"%s\" passed to function %s, "\
                             "ignoring.", neat_tag_name[optional[i].tag], __func__);\
                    break;\
                };\
            }\
        }\
    } while (0);

neat_error_code neat_security_install(neat_ctx *ctx, neat_flow *flow);
void            nt_security_init(neat_ctx *ctx);
void            nt_security_close(neat_ctx *ctx);
void uvpollable_cb(uv_poll_t *handle, int status, int events);
neat_error_code nt_dtls_install(neat_ctx *ctx, struct neat_pollable_socket *sock);
neat_error_code nt_dtls_connect(neat_ctx *ctx, neat_flow *flow);
neat_error_code copy_dtls_data(struct neat_pollable_socket *newSocket, struct neat_pollable_socket *socket);
neat_error_code nt_sctp_open_stream(struct neat_pollable_socket *socket, uint16_t sid);

/* Declarations for WebRTC */
#if defined(WEBRTC_SUPPORT)
void neat_webrtc_gather_candidates(neat_ctx *ctx, neat_flow *flow, uint16_t role, const char *channel_name);
void neat_set_listening_flow(neat_ctx *ctx, neat_flow *flow);
void webrtc_io_connected(neat_ctx *ctx, neat_flow *flow, neat_error_code code);
void webrtc_io_readable(neat_ctx *ctx, neat_flow *flow, neat_error_code code, void *buffer, size_t size);
void webrtc_io_writable(neat_ctx *ctx, neat_flow *flow, neat_error_code code);
neat_error_code neat_webrtc_write_to_channel(struct neat_ctx *ctx, struct neat_flow *flow,
    const unsigned char *buffer, uint32_t amt, struct neat_tlv optional[], unsigned int opt_count);
void webrtc_io_parameters(neat_ctx *ctx, neat_flow *flow, neat_error_code code);
#endif // #if defined(WEBRTC_SUPPORT)
#endif
