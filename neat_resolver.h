#ifndef NEAT_RESOLVE_H
#define NEAT_RESOLVE_H

#include <uv.h>
#include <ldns/ldns.h>

#include "neat_internal.h"
#include "neat_queue.h"
#include "neat_addr.h"

//Timeout for complete DNS query
#define DNS_TIMEOUT             30000
//Timeout after first good reply
#define DNS_RESOLVED_TIMEOUT    1000
#define DNS_LITERAL_TIMEOUT     1000
#define DNS_BUF_SIZE            1472
#define MAX_NUM_RESOLVED        3
#define NO_PROTOCOL             0xFFFFFFFF

//We know these servers will not lie and will accept queries from an network
//address. Until we have defined a syntax for IP/interface information in
//resolv.conf (and the like), then this is as good as we can do
//TODO: Some firewalls like to block these, implement a platform-independent way of reading from resolv.conf etc.
static char* const INET_DNS_SERVERS [] = {"8.8.8.8", "8.8.4.4", "208.67.222.222", "208.67.220.220"};
static char* const INET6_DNS_SERVERS [] = {"2001:4860:4860::8888", "2001:4860:4860::8844", "2620:0:ccc::2", "2620:0:ccd::2"};

struct neat_addr;
struct neat_resolver_request;

TAILQ_HEAD(neat_resolver_request_queue, neat_resolver_request);
struct neat_resolver {
    //The resolver will wrap the context, so that we can easily have many
    //resolvers
    struct neat_ctx *nc;

    //DNS timeout before any domain has been resolved
    uint16_t dns_t1;
    //DNS timeout after at least one domain has been resolved
    uint16_t dns_t2;

    //Will be set to 1 if we are going to free resolver in idle
    //TODO: Will most likely be changed to a state variable
    uint8_t free_resolver;
    //Flag used to signal if we have resolved name and timeout has switched from
    //total DNS timeout
    uint8_t name_resolved_timeout;

    //Flag set when the resolv.conf file monitoring has been closed. Must be
    //done before we can free resolver
    uint8_t fs_event_closed;
    uint8_t __pad1;

    //The reason we need two of these is that as of now, a neat_event_cb
    //struct can only be part of one list. This is a future optimization, if we
    //decide that it is a problem
    struct neat_event_cb newaddr_cb;
    struct neat_event_cb deladdr_cb;

    //Keep track of all DNS servers seen until now
    struct neat_resolver_servers server_list;

    //Need to defer free until libuv has clean up memory. Keep this list here as
    //an optimization, for example we don't have to have one idle handle per
    //request
    struct neat_resolver_pairs resolver_pairs_del;
    uv_idle_t idle_handle;
    uv_timer_t timeout_handle;
    uv_fs_event_t resolv_conf_handle;

    //DNS request queue, using TAILQ
    struct neat_resolver_request_queue request_queue;
    struct neat_resolver_request_queue dead_request_queue;
};

//Represent one source/dst address used for DNS lookups. We could save space by
//recycling handle, but this structure will make it easier to support
//fragmentation of DNS requests (way down the line)
struct neat_resolver_src_dst_addr {
    struct neat_resolver *resolver; //TODO: Remove
    struct neat_resolver_request *request;
    struct neat_addr *src_addr;
    //TODO: Dynamically allocate?
    struct neat_addr dst_addr;

    char dns_rcv_buf[DNS_BUF_SIZE];
    ldns_buffer *dns_snd_buf;
    uv_buf_t dns_uv_snd_buf;
    uv_udp_send_t dns_snd_handle;
    uv_udp_t resolve_handle;

    LIST_ENTRY(neat_resolver_src_dst_addr) next_pair;

    //TODO: Consider designing a better algorithm for selecting servers when
    //there are multiple answers, than just picking first MAX_NUM_RESOLVED
    struct sockaddr_storage resolved_addr[MAX_NUM_RESOLVED];

    //Keep track of which pairs are closed
    uint8_t closed;
};

//Struct representing one DNS request
//TODO: Might be moved to neat_internal.h, will probably be passed to callback
struct neat_resolver_request {
    uint16_t dst_port;
    uint8_t family;
    uint8_t name_resolved_timeout;
    struct neat_resolver *resolver;

    char domain_name[MAX_DOMAIN_LENGTH];

    //The resolver pairs related to this request
    struct neat_resolver_pairs resolver_pairs;

    //Callback that will be called when resolving is done
    neat_resolver_handle_t resolve_cb; 

    //Timeout handle owned by this request
    uv_timer_t timeout_handle;

    void *user_data; //User data

    TAILQ_ENTRY(neat_resolver_request) next_req;
    TAILQ_ENTRY(neat_resolver_request) next_dead_req;
};

#endif
