#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <string.h>
#include <uv.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ldns/ldns.h>

#ifdef __linux__
    #include <net/if.h>
#endif

// todo - dotted decimals, localhost, /etc/hosts may not work here..

#include "neat.h"
#include "neat_internal.h"
#include "neat_core.h"
#include "neat_addr.h"
#include "neat_resolver.h"

static uint8_t neat_resolver_create_pairs(struct neat_resolver *resolver,
        struct neat_addr *src_addr);
static void neat_resolver_delete_pairs(struct neat_resolver *resolver,
        struct neat_addr *addr_to_delete);

//NEAT internal callbacks, not very interesting
static void neat_resolver_handle_newaddr(struct neat_ctx *nc,
                                         void *p_ptr,
                                         void *data)
{
    struct neat_resolver *resolver = p_ptr;
    struct neat_addr *src_addr = data;

    if (resolver->family && resolver->family != src_addr->family)
        return;

    //Ignore addresses that are deprecated
    if (src_addr->family == AF_INET6 && !src_addr->u.v6.ifa_pref)
        return;

    neat_resolver_create_pairs(resolver, src_addr);
}

static void neat_resolver_handle_deladdr(struct neat_ctx *nic,
                                         void *p_ptr,
                                         void *data)
{
    struct neat_resolver *resolver = p_ptr;
    struct neat_addr *src_addr = data;
    struct sockaddr_in *src_addr4;
    struct sockaddr_in6 *src_addr6;
    char addr_str[INET6_ADDRSTRLEN];

    if (src_addr->family == AF_INET) {
        src_addr4 = &(src_addr->u.v4.addr4);
        inet_ntop(AF_INET, &(src_addr4->sin_addr), addr_str, INET_ADDRSTRLEN);
    } else {
        src_addr6 = &(src_addr->u.v6.addr6);
        inet_ntop(AF_INET6, &(src_addr6->sin6_addr), addr_str, INET6_ADDRSTRLEN);
    }

    printf("Deleted %s\n", addr_str);

    neat_resolver_delete_pairs(resolver, src_addr);
}

//libuv-specific callbacks

//This callback is called when we close a UDP socket (handle) and allows us to
//free any allocated resource. In our case, this is only the dns_snd_buf
static void neat_resolver_close_cb(uv_handle_t *handle)
{
    struct neat_resolver_src_dst_addr *resolver_pair = handle->data;

    if (resolver_pair->dns_snd_buf)
        ldns_buffer_free(resolver_pair->dns_snd_buf);

    //Mark that it is safe to free/remove this pair
    resolver_pair->closed = 1;
}

//This callback is called before libuv polls for I/O and is by default run on
//every iteration. We use it to free memory used by the resolver, and it is only
//active when this is relevant. I.e., we only start the idle handle when
//resolver_pairs_del is not empty
static void neat_resolver_idle_cb(uv_idle_t *handle)
{
    struct neat_resolver *resolver = handle->data;
    struct neat_resolver_src_dst_addr *resolver_pair, *resolver_itr;

    resolver_itr = resolver->resolver_pairs_del.lh_first;

    while (resolver_itr != NULL) {
        resolver_pair = resolver_itr;
        resolver_itr = resolver_itr->next_pair.le_next;

        if (!resolver_pair->closed)
            continue;

        LIST_REMOVE(resolver_pair, next_pair);
        free(resolver_pair);
    }

    //We cant stop idle until all pairs marked for deletion have been removed
    if (resolver->resolver_pairs_del.lh_first)
        return;

    uv_idle_stop(&(resolver->idle_handle));

    //Only call cleanup when library user has marked that it is safe
    if (resolver->free_resolver && resolver->cleanup)
        resolver->cleanup(resolver);
}

static uint8_t neat_resolver_addr_internal(struct sockaddr_storage *addr)
{
    struct sockaddr_in *addr4 = NULL;
    struct sockaddr_in6 *addr6 = NULL;
    uint32_t haddr4 = 0;
    
    if (addr->ss_family == AF_INET6) {
        addr6 = (struct sockaddr_in6*) addr;
        return (addr6->sin6_addr.s6_addr[0] & 0xfe) != 0xfc;
    }

    addr4 = (struct sockaddr_in*) addr;
    haddr4 = ntohl(addr4->sin_addr.s_addr);

    if ((haddr4 & IANA_A_MASK) == IANA_A_NW ||
        (haddr4 & IANA_B_MASK) == IANA_B_NW ||
        (haddr4 & IANA_C_MASK) == IANA_C_NW)
        return 1;
    else
        return 0;
}

//Called when timeout expires. This function will pass the results of the DNS
//query to the application using NEAT
static void neat_resolver_timeout_cb(uv_timer_t *handle)
{
    struct neat_resolver *resolver = handle->data;
    struct neat_resolver_src_dst_addr *pair_itr = NULL;
    struct neat_resolver_results *result_list;
    struct neat_resolver_res *result;
    uint32_t num_resolved_addrs = 0;
    struct sockaddr_in *addr4 = NULL;
    socklen_t addrlen = 0;
    uint8_t i;

    //DNS timeout, call DNS callback with timeout error code
    if (!resolver->name_resolved_timeout) {
        resolver->handle_resolve(resolver, NULL, NEAT_RESOLVER_TIMEOUT);
        return;
    }

    //Signal internal error
    if ((result_list = 
                calloc(sizeof(struct neat_resolver_results), 1)) == NULL) {
        resolver->handle_resolve(resolver, NULL, NEAT_RESOLVER_ERROR);
        return;
    }

    LIST_INIT(result_list);
    pair_itr = resolver->resolver_pairs.lh_first;

    //Iterate through all receiver pairs and create neat_resolver_res
    while (pair_itr != NULL) {
        if (!pair_itr->resolved_addr[0].ss_family) {
            pair_itr = pair_itr->next_pair.le_next;
            continue;
        }

        for (i = 0; i < MAX_NUM_RESOLVED; i++) {
            //Resolved addresses are added linearly
            if (!pair_itr->resolved_addr[i].ss_family)
                break;

            //We dont care if one fails, only if all
            if ((result = calloc(sizeof(struct neat_resolver_res), 1)) == NULL)
                continue;

            addrlen = pair_itr->src_addr->family == AF_INET ?
                sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

            result->ai_family = pair_itr->src_addr->family;
            result->ai_socktype = resolver->ai_socktype;
            result->ai_protocol = resolver->ai_protocol;
            result->if_idx = pair_itr->src_addr->if_idx;
            result->src_addr = pair_itr->src_addr->u.generic.addr;
            result->src_addr_len = addrlen;
            result->dst_addr = pair_itr->resolved_addr[i];
            result->dst_addr_len = addrlen;
            result->internal = neat_resolver_addr_internal(&(result->dst_addr));

            //Head of sockaddr_in and sockaddr_in6 is the same, so this is safe
            //for setting port
            addr4 = (struct sockaddr_in*) &(result->dst_addr);
            addr4->sin_port = resolver->dst_port;

            LIST_INSERT_HEAD(result_list, result, next_res);
            num_resolved_addrs++;
        }

        pair_itr = pair_itr->next_pair.le_next;
    }

    if (!num_resolved_addrs)
        resolver->handle_resolve(resolver, NULL, NEAT_RESOLVER_ERROR);
    else
        resolver->handle_resolve(resolver, result_list, NEAT_RESOLVER_OK);
}

//Called when a DNS request has been (i.e., passed to socket). We will send the
//second query (used for checking poisoning) here. If that is needed
static void neat_resolver_dns_sent_cb(uv_udp_send_t *req, int status)
{
    //Callback will be used to send the follow-up request to check for errors
    //printf("UDP send callback\n");
}

//libuv gives the user control of how memory is allocated. This callback is
//called when a UDP packet is ready to received, and we have to fill out the
//provided buf with the storage location (and available size)
static void neat_resolver_dns_alloc_cb(uv_handle_t *handle,
        size_t suggested_size, uv_buf_t *buf)
{
    struct neat_resolver_src_dst_addr *pair = handle->data;

    buf->base = pair->dns_rcv_buf;
    buf->len = sizeof(pair->dns_rcv_buf);
}

//Internal NEAT resolver functions
//Deletes have to happen async so that libuv can do internal clean-up. I.e., we
//can't just free memory and that is that. This function marks a resolver pair
//as ready for deletion
static void neat_resolver_mark_pair_del(struct neat_resolver_src_dst_addr *pair)
{
    struct neat_resolver *resolver = pair->resolver;

    //If handle is not active/receiving, this is just a noop
    uv_udp_recv_stop(&(pair->resolve_handle));
    uv_close((uv_handle_t*) &(pair->resolve_handle), neat_resolver_close_cb);

    if (pair->next_pair.le_next != NULL || pair->next_pair.le_prev != NULL)
        LIST_REMOVE(pair, next_pair);

    LIST_INSERT_HEAD(&(resolver->resolver_pairs_del), pair,
            next_pair);

    //We can't free memory right away, libuv has to be allowed to
    //perform internal clean-up first. This is done after loop is done
    //(uv__run_closing_handles), so we use idle (which is called in the
    //next iteration and before polling)
    if (!uv_is_active((uv_handle_t*) &(resolver->idle_handle)))
        uv_idle_start(&(resolver->idle_handle), neat_resolver_idle_cb);
}

//Receive and parse a DNS reply
//TODO: Refactor and make large parts helper function?
static void neat_resolver_dns_recv_cb(uv_udp_t* handle, ssize_t nread,
        const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    struct neat_resolver_src_dst_addr *pair = handle->data;
    ldns_pkt *dns_reply;
    //Used to store the results of the DNS query
    ldns_rr_list *rr_list = NULL;
    ldns_rr *rr_record = NULL;
    ldns_buffer *host_addr = NULL;
    ldns_rdf *rdf_result = NULL;
    ldns_rr_type rr_type;
    size_t retval, rr_count, i;
    uint8_t num_resolved = 0, pton_failed = 0;
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;

    if (nread == 0 && addr == NULL)
        return;
  
    retval = ldns_wire2pkt(&dns_reply, (const uint8_t*) buf->base, nread);

    if (retval != LDNS_STATUS_OK)
        return;

    if (pair->src_addr->family == AF_INET)
        rr_type = LDNS_RR_TYPE_A;
    else
        rr_type = LDNS_RR_TYPE_AAAA;

    //Parse result
    rr_list = ldns_pkt_rr_list_by_type(dns_reply, rr_type, LDNS_SECTION_ANSWER);

    if (rr_list == NULL) {
        ldns_pkt_free(dns_reply);
        return;
    }

    rr_count = ldns_rr_list_rr_count(rr_list);

    if (!rr_count) {
        ldns_rr_list_deep_free(rr_list);
        ldns_pkt_free(dns_reply);
        return;
    }

    for (i=0; i<rr_count; i++) {
        rr_record = ldns_rr_list_rr(rr_list, i);
        rdf_result = ldns_rr_rdf(rr_record, 0);
        host_addr = ldns_buffer_new(ldns_rdf_size(rdf_result));

        if(!host_addr)
            continue;

        if (pair->src_addr->family == AF_INET) {
            ldns_rdf2buffer_str_a(host_addr, rdf_result);
            addr4 = (struct sockaddr_in*) &(pair->resolved_addr[num_resolved]);

            if (!inet_pton(AF_INET, (const char*) ldns_buffer_begin(host_addr),
                    &(addr4->sin_addr)))
                pton_failed = 1;
            else
                addr4->sin_family = AF_INET;
        } else {
            ldns_rdf2buffer_str_aaaa(host_addr, rdf_result);
            addr6 = (struct sockaddr_in6*) &(pair->resolved_addr[num_resolved]);

            if (!inet_pton(AF_INET6, (const char*) ldns_buffer_begin(host_addr),
                    &(addr6->sin6_addr)))
                pton_failed = 1;
            else
                addr6->sin6_family = AF_INET6;
        }
 
        if (!pton_failed)
            num_resolved++;
        else
            pton_failed = 0;

        ldns_buffer_free(host_addr);
       
        if (num_resolved >= MAX_NUM_RESOLVED)
            break;
    }

    ldns_rr_list_deep_free(rr_list);
    ldns_pkt_free(dns_reply);

    if (num_resolved && !pair->resolver->name_resolved_timeout){
        uv_timer_stop(&(pair->resolver->timeout_handle));
        uv_timer_start(&(pair->resolver->timeout_handle), neat_resolver_timeout_cb,
                pair->resolver->dns_t2, 0);
        pair->resolver->name_resolved_timeout = 1;
    }
}

//Prepare and send (or, start sending) a DNS query for the given service
static uint8_t neat_resolver_send_query(struct neat_resolver_src_dst_addr *pair)
{
    ldns_pkt *pkt;
    ldns_rr_type rr_type;

    if (pair->src_addr->family == AF_INET)
        rr_type = LDNS_RR_TYPE_A;
    else
        rr_type = LDNS_RR_TYPE_AAAA;

    //Create a DNS query for aUrl
    if (ldns_pkt_query_new_frm_str(&pkt, pair->resolver->domain_name, rr_type,
                LDNS_RR_CLASS_IN, 0) != LDNS_STATUS_OK) {
        fprintf(stderr, "Could not create DNS packet");
        return RETVAL_FAILURE;
    }

    ldns_pkt_set_random_id(pkt);

    //We are a naive stub-resolver, so we need the server we query to do most of
    //the work for us
    ldns_pkt_set_rd(pkt, 1);
    ldns_pkt_set_ad(pkt, 1);

    //Convert internal LDNS structure to query buffer
    pair->dns_snd_buf = ldns_buffer_new(LDNS_MIN_BUFLEN);
    if (ldns_pkt2buffer_wire(pair->dns_snd_buf, pkt) != LDNS_STATUS_OK) {
        fprintf(stderr, "Could not convert pkt to buf");
        ldns_pkt_free(pkt);
        return RETVAL_FAILURE;
    }

    ldns_pkt_free(pkt);

    pair->dns_uv_snd_buf.base = (char*) ldns_buffer_begin(pair->dns_snd_buf);
    pair->dns_uv_snd_buf.len = ldns_buffer_position(pair->dns_snd_buf);

    if (uv_udp_send(&(pair->dns_snd_handle), &(pair->resolve_handle),
            &(pair->dns_uv_snd_buf), 1,
            (const struct sockaddr*) &(pair->dst_addr.u.generic.addr),
            neat_resolver_dns_sent_cb)) {
        fprintf(stderr, "Failed to start DNS send\n");
        return RETVAL_FAILURE;
    }

    return RETVAL_SUCCESS;
}

//Create one SRC/DST DNS resolver pair. Pair has already been allocated
static uint8_t neat_resolver_create_pair(struct neat_ctx *nc,
        struct neat_resolver_src_dst_addr *pair,
        const char *dst_addr_str)
{
    struct sockaddr_in *dst_addr4;
    struct sockaddr_in6 *dst_addr6;
    void *dst_addr_pton = NULL;
    uint8_t family = pair->src_addr->family;
#ifdef __linux__
    uv_os_fd_t socket_fd = -1;
    char if_name[IF_NAMESIZE];
#endif

    if (family == AF_INET) {
        dst_addr4 = &(pair->dst_addr.u.v4.addr4);
        dst_addr4->sin_family = AF_INET;
        dst_addr4->sin_port = htons(LDNS_PORT);
        dst_addr_pton = &(dst_addr4->sin_addr);
    } else {
        dst_addr6 = &(pair->dst_addr.u.v6.addr6);
        dst_addr6->sin6_family = AF_INET6;
        dst_addr6->sin6_port = htons(LDNS_PORT);
        dst_addr_pton = &(dst_addr6->sin6_addr);
    }

    if (!inet_pton(family, dst_addr_str, dst_addr_pton)) {
        fprintf(stderr, "Failed to convert destionation address\n");
        return RETVAL_FAILURE;
    }

    //Configure uv_udp_handle
    if (uv_udp_init(nc->loop, &(pair->resolve_handle))) {
        //Closed is normally set in close_cb, but since we will never get that
        //far, set it here instead
        //pair->closed = 1;
        fprintf(stderr, "Failure to initialize UDP handle\n");
        return RETVAL_FAILURE;
    }

    pair->resolve_handle.data = pair;

    if (uv_udp_bind(&(pair->resolve_handle),
                (struct sockaddr*) &(pair->src_addr->u.generic.addr),
                0)) {
        fprintf(stderr, "Failed to bind UDP socket\n");
        return RETVAL_FAILURE;
    }

    if (uv_udp_recv_start(&(pair->resolve_handle), neat_resolver_dns_alloc_cb,
                neat_resolver_dns_recv_cb)) {
        fprintf(stderr, "Failed to start receiving UDP\n");
        return RETVAL_FAILURE;
    }

//TODO: Binding to interface name requires sudo, not sure if that is acceptable.
//Ignore any error here for now
#ifdef __linux__
    uv_fileno((uv_handle_t*) &(pair->resolve_handle), &socket_fd);

    if (!if_indextoname(pair->src_addr->if_idx, if_name)) {
        /*fprintf(stderr, "Could not get interface name for index %u\n",
                pair->src_addr->if_idx);*/
        return RETVAL_IGNORE;
    }

    if (setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, if_name,
                strlen(if_name)) < 0) {
        //fprintf(stderr, "Could not bind socket to interface %s\n", if_name);
        return RETVAL_IGNORE;
    }
#endif

    return RETVAL_SUCCESS;
}

//Called when we get a NEAT_NEWADDR message. Go through all matching DNS
//servers, try to create src/dst pair and send query
static uint8_t neat_resolver_create_pairs(struct neat_resolver *resolver,
        struct neat_addr *src_addr)
{
    const char **dns_addrs = (const char **) ((src_addr->family == AF_INET) ?
            INET_DNS_SERVERS : INET6_DNS_SERVERS);
    uint8_t num_dns = src_addr->family == AF_INET ? sizeof(INET_DNS_SERVERS) :
        sizeof(INET6_DNS_SERVERS);
    uint8_t i;
    struct neat_resolver_src_dst_addr *resolver_pair;

    //After adding support for restart, we can end up here without a domain
    //name. There is not point continuing if we have no domain name to resolve
    if (!resolver->domain_name[0])
        return RETVAL_SUCCESS;

    num_dns /= sizeof(const char*);

    for (i = 0; i < num_dns; i++) {
        resolver_pair = (struct neat_resolver_src_dst_addr*)
            calloc(sizeof(struct neat_resolver_src_dst_addr), 1);

        if (!resolver_pair) {
            fprintf(stderr, "Failed to allocate memory for resolver pair\n");
            continue;
        }

        resolver_pair->resolver = resolver;
        resolver_pair->src_addr = src_addr;

        if (neat_resolver_create_pair(resolver->nc, resolver_pair,
                    dns_addrs[i]) == RETVAL_FAILURE) {
            fprintf(stderr, "Failed to create resolver pair\n");
            neat_resolver_mark_pair_del(resolver_pair);
            continue;
        }

        if (neat_resolver_send_query(resolver_pair)) {
            fprintf(stderr, "Failed to start lookup\n");
            neat_resolver_mark_pair_del(resolver_pair);
        } else {
            //printf("Will lookup %s\n", resolver->domain_name);
            LIST_INSERT_HEAD(&(resolver->resolver_pairs), resolver_pair,
                    next_pair);
        }
    }

    //Start DNS no reply timeout
    if (!uv_is_active((const uv_handle_t *) &(resolver->timeout_handle)))
        uv_timer_start(&(resolver->timeout_handle), neat_resolver_timeout_cb,
                resolver->dns_t1, 0);

    return RETVAL_SUCCESS;
}

//Called when we get a NEAT_DELADDR message. Go though all resolve pairs and
//remove those where src. address match the deleted address
static void neat_resolver_delete_pairs(struct neat_resolver *resolver,
        struct neat_addr *addr_to_delete)
{
    struct sockaddr_in *addr4 = NULL, *addr4_cmp;
    struct sockaddr_in6 *addr6 = NULL, *addr6_cmp;
    struct neat_resolver_src_dst_addr *resolver_pair, *resolver_itr;

    if (addr_to_delete->family == AF_INET)
        addr4 = &(addr_to_delete->u.v4.addr4);
    else
        addr6 = &(addr_to_delete->u.v6.addr6);

    resolver_itr = resolver->resolver_pairs.lh_first;

    while (resolver_itr != NULL) {
        resolver_pair = resolver_itr;
        resolver_itr = resolver_itr->next_pair.le_next;

        if (resolver_pair->src_addr->family != addr_to_delete->family)
            continue;

        if (addr_to_delete->family == AF_INET) {
            addr4_cmp = &(resolver_pair->src_addr->u.v4.addr4);

            if (addr4_cmp->sin_addr.s_addr == addr4->sin_addr.s_addr)
                neat_resolver_mark_pair_del(resolver_pair);
        } else {
            addr6_cmp = &(resolver_pair->src_addr->u.v6.addr6);

            if (neat_addr_cmp_ip6_addr(addr6_cmp->sin6_addr, addr6->sin6_addr))
                neat_resolver_mark_pair_del(resolver_pair);
        }
    }
}

//Check if node is an IP literal or not. Returns -1 on failure, 0 if not
//literal, 1 if literal
int8_t neat_resolver_check_for_literal(uint8_t family, const char *node)
{
    struct in6_addr dummy_addr;
    int32_t v4_literal = 0, v6_literal = 0;

    //The only time inet_pton fails is if the system lacks v4/v6 support. This
    //should rather be handled with an ifdef + check at compile time
    v4_literal = inet_pton(AF_INET, node, &dummy_addr);
    v6_literal = inet_pton(AF_INET6, node, &dummy_addr);

    //These are the three error cases
    //- if family if unspec, node has to be a domain name as we can't know which
    //literal was intended to be used.
    //- if family is v4 and address is v6 (or opposite), then user has made a
    //mistake and must be notifed
    if ((family == AF_UNSPEC && (v4_literal || v6_literal))) {
        fprintf(stderr, "AF_UNSPEC and literals are not supported\n");
        return -1;
    } else if ((family == AF_INET && v6_literal) ||
               (family == AF_INET6 && v4_literal)) {
        fprintf(stderr, "Mismatch between family and literal\n");
        return -1;
    }

    return v4_literal | v6_literal;
}

//Public NEAT resolver functions
//getaddrinfo starts a query for the provided service
//TODO: Expand parameter list
uint8_t neat_getaddrinfo(struct neat_resolver *resolver, uint8_t family,
    const char *node, const char *service, int ai_socktype, int ai_protocol)
{
    struct sockaddr_storage remote_addr;
    struct neat_addr *nsrc_addr = NULL;
    int32_t dst_port = 0;
    int8_t retval;

    dst_port = atoi(service);

    if (dst_port <= 0 || dst_port > UINT16_MAX) {
        fprintf(stderr, "Invalid service specified\n");
        return RETVAL_FAILURE;
    }

    resolver->family = family;
    resolver->ai_socktype = ai_socktype;
    resolver->ai_protocol = ai_protocol;
    resolver->dst_port = htons(dst_port);

    if ((strlen(node) + 1) > MAX_DOMAIN_LENGTH) {
        fprintf(stderr, "Domain name too long\n");
        return RETVAL_FAILURE;
    }

    retval = neat_resolver_check_for_literal(family, node);

    fprintf(stdout, "Retval from literal check: %d\n", retval);

    return RETVAL_FAILURE;

#if 0
    //TODO: Decide what to do here, when we get an IP address there is no need
    //for lookup. How to deal with addresses, start a timeout right away?
    if (inet_pton(family, node, &remote_addr) == 1) {
        fprintf(stderr, "Service is an IP address or does not match family\n");
        return RETVAL_FAILURE;
    }
#endif

    //No need to care about \0, we use calloc ...
    memcpy(resolver->domain_name, node, strlen(node));

    //No point starting to query if we don't have any source addresses
    if (!resolver->nc->src_addr_cnt) {
        fprintf(stderr, "No available src addresses\n");
        return RETVAL_SUCCESS;
    }

    //Iterate through src addresses, create udp sockets and start requesting
    for (nsrc_addr = resolver->nc->src_addrs.lh_first; nsrc_addr != NULL;
            nsrc_addr = nsrc_addr->next_addr.le_next) {

        if (resolver->family && nsrc_addr->family != resolver->family)
            continue;

        //Do not use deprecated addresses
        if (nsrc_addr->family == AF_INET6 && !nsrc_addr->u.v6.ifa_pref)
            continue;

        neat_resolver_create_pairs(resolver, nsrc_addr);
    }

    //Iterate through available addresses and start sending DNS queries
    return RETVAL_SUCCESS;
}

//Initialize the resolver. Set up callbacks etc.
struct neat_resolver *
neat_resolver_init(struct neat_ctx *nc,
                   neat_resolver_handle_t handle_resolve, neat_resolver_cleanup_t cleanup)
{
    struct neat_resolver *resolver = calloc(sizeof(struct neat_resolver), 1);
    if (!handle_resolve || !resolver)
        return NULL;

    resolver->nc = nc;
    resolver->cleanup = cleanup;
    resolver->handle_resolve = handle_resolve;
    resolver->dns_t1 = DNS_TIMEOUT;
    resolver->dns_t2 = DNS_RESOLVED_TIMEOUT;

    resolver->newaddr_cb.event_cb = neat_resolver_handle_newaddr;
    resolver->newaddr_cb.data = resolver;
    resolver->deladdr_cb.event_cb = neat_resolver_handle_deladdr;
    resolver->deladdr_cb.data = resolver;

    if (neat_add_event_cb(nc, NEAT_NEWADDR, &(resolver->newaddr_cb)) ||
        neat_add_event_cb(nc, NEAT_DELADDR, &(resolver->deladdr_cb))) {
        fprintf(stderr, "Could not add one or more resolver callbacks\n");
        return NULL;
    }

    LIST_INIT(&(resolver->resolver_pairs));
    LIST_INIT(&(resolver->resolver_pairs_del));

    uv_idle_init(nc->loop, &(resolver->idle_handle));
    resolver->idle_handle.data = resolver;
    uv_timer_init(nc->loop, &(resolver->timeout_handle));
    resolver->timeout_handle.data = resolver;

    return resolver;
}

//Helper function used by both cleanup and reset
static void neat_resolver_cleanup(struct neat_resolver *resolver, uint8_t free_mem)
{
    struct neat_resolver_src_dst_addr *resolver_pair, *resolver_itr;

    resolver_itr = resolver->resolver_pairs.lh_first;

    while (resolver_itr != NULL) {
        resolver_pair = resolver_itr;
        resolver_itr = resolver_itr->next_pair.le_next;
        neat_resolver_mark_pair_del(resolver_pair);
    }

    resolver->free_resolver = free_mem;
    resolver->name_resolved_timeout = 0;

    if (uv_is_active((const uv_handle_t*) &(resolver->timeout_handle)))
        uv_timer_stop(&(resolver->timeout_handle));

    //We need to do this here, in addition to in mark_pair_del, since we might
    //get in the situation where there are zero addresses to delete (for example
    //if resolver is freed before there are no source addresses)
    if (!uv_is_active((const uv_handle_t*) &(resolver->idle_handle)))
        uv_idle_start(&(resolver->idle_handle), neat_resolver_idle_cb);

    //Unsubscribe from callbacks if we are going to release memory
    if (free_mem) {
        neat_remove_event_cb(resolver->nc, NEAT_NEWADDR, &(resolver->newaddr_cb));
        neat_remove_event_cb(resolver->nc, NEAT_DELADDR, &(resolver->deladdr_cb));
    } else {
        memset(resolver->domain_name, 0, MAX_DOMAIN_LENGTH);
    }
}

void neat_resolver_reset(struct neat_resolver *resolver)
{
    neat_resolver_cleanup(resolver, 0);
}

void neat_resolver_free(struct neat_resolver *resolver)
{
    neat_resolver_cleanup(resolver, 1);
    free(resolver);
}

void neat_resolver_free_results(struct neat_resolver_results *results)
{
    struct neat_resolver_res *result, *res_itr;

    res_itr = results->lh_first;

    while (res_itr != NULL) {
        result = res_itr;
        res_itr = res_itr->next_res.le_next;
        free(result);
    }

    free(results);
}

void neat_resolver_update_timeouts(struct neat_resolver *resolver, uint16_t t1,
        uint16_t t2)
{
    resolver->dns_t1 = t1;
    resolver->dns_t2 = t2;
}
