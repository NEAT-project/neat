#ifndef NEAT_RESOLVE_H
#define NEAT_RESOLVE_H

#include <uv.h>
#include <ldns/ldns.h>

#include "neat_internal.h"
#include "neat_queue.h"

//Timeout for complete DNS query
#define DNS_TIMEOUT             30000
//Timeout after first good reply
#define DNS_RESOLVED_TIMEOUT    1000
#define DNS_LITERAL_TIMEOUT     100
#define DNS_BUF_SIZE            1472
#define MAX_NUM_RESOLVED        3
#define NO_PROTOCOL             0xFFFFFFFF

//These are the private networks defined by IANA. We use them to check if we end
//up in the private network after following redirects
#define IANA_A_NW           0x0a000000 //10.0.0.0
#define IANA_A_MASK         0xff000000 //255.0.0.0 (8)
#define IANA_B_NW           0xac100000 //172.16.0.0
#define IANA_B_MASK         0xfff00000 //255.240.0.0 (12)
#define IANA_C_NW           0xc0a80000 //192.168.0.0
#define IANA_C_MASK         0xffff0000 //255.255.0.0 (16)

//We know these servers will not lie and will accept queries from an network
//address. Until we have defined a syntax for IP/interface information in
//resolv.conf (and the like), then this is as good as we can do
//TODO: Some firewalls like to block these, implement a platform-independent way of reading from resolv.conf etc.
static char* const INET_DNS_SERVERS [] = {"8.8.8.8", "8.8.4.4", "208.67.222.222", "208.67.220.220"};
static char* const INET6_DNS_SERVERS [] = {"2001:4860:4860::8888", "2001:4860:4860::8844", "2620:0:ccc::2", "2620:0:ccd::2"};

struct neat_addr;
struct neat_resolver;

//Represent one source/dst address used for DNS lookups. We could save space by
//recycling handle, but this structure will make it easier to support
//fragmentation of DNS requests (way down the line)
struct neat_resolver_src_dst_addr {
    struct neat_resolver *resolver;
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
    uint8_t __pad;

    char domain_name[MAX_DOMAIN_LENGTH];

    neat_resolver_handle_t *cb; //Callback that will be called when resolving is done

    //These values are just passed on to neat_resolver_res
    //TODO: Remove this, will be set on result
    //WHAT IS THIS? Causes a large number of allocs ...
    neat_protocol_stack_type ai_stack[NEAT_STACK_MAX_NUM];

    void *data; //User data

    TAILQ_ENTRY(neat_resolver_request) next_req;
};

#endif
