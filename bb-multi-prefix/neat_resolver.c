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

#ifdef LINUX
    #include <net/if.h>
#endif

#include "neat.h"
#include "neat_core.h"
#include "neat_addr.h"
#include "neat_resolver.h"

static uint8_t neat_resolver_create_pair(struct neat_resolver *resolver,
        struct neat_addr *src_addr);

static void neat_resolver_handle_newaddr(struct neat_ctx *nc,
                                         void *p_ptr,
                                         void *data)
{
    struct neat_resolver *resolver = p_ptr;
    struct neat_addr *src_addr = data;

    if (resolver->family && resolver->family != src_addr->family)
        return;

    neat_resolver_create_pair(resolver, src_addr);
}

static void neat_resolver_handle_updateaddr(struct neat_ctx *nc,
                                            void *p_ptr,
                                            void *data)
{
    struct neat_addr *src_addr = data;
    struct sockaddr_in *src_addr4;
    struct sockaddr_in6 *src_addr6;
    char addr_str[INET6_ADDRSTRLEN];

    if (src_addr->family == AF_INET) {
        src_addr4 = (struct sockaddr_in*) &(src_addr->u.generic.addr);
        inet_ntop(AF_INET, &(src_addr4->sin_addr), addr_str, INET_ADDRSTRLEN);
    } else {
        src_addr6 = (struct sockaddr_in6*) &(src_addr->u.generic.addr);
        inet_ntop(AF_INET6, &(src_addr6->sin6_addr), addr_str, INET6_ADDRSTRLEN);
    }

    printf("Updated %s\n", addr_str);
}

static void neat_resolver_handle_deladdr(struct neat_ctx *nic,
                                         void *p_ptr,
                                         void *data)
{
    struct neat_addr *src_addr = data;
    struct sockaddr_in *src_addr4;
    struct sockaddr_in6 *src_addr6;
    char addr_str[INET6_ADDRSTRLEN];

    if (src_addr->family == AF_INET) {
        src_addr4 = (struct sockaddr_in*) &(src_addr->u.generic.addr);
        inet_ntop(AF_INET, &(src_addr4->sin_addr), addr_str, INET_ADDRSTRLEN);
    } else {
        src_addr6 = (struct sockaddr_in6*) &(src_addr->u.generic.addr);
        inet_ntop(AF_INET6, &(src_addr6->sin6_addr), addr_str, INET6_ADDRSTRLEN);
    }

    printf("Deleted %s\n", addr_str);
}

static void neat_resolver_close_cb(uv_handle_t *handle)
{
    struct neat_resolver_src_dst_addr *resolver_pair = handle->data;

    if (resolver_pair->dns_snd_buf)
        ldns_buffer_free(resolver_pair->dns_snd_buf);

    resolver_pair->closed = 1;
}

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

    //Until next time
    uv_idle_stop(&(resolver->idle_handle));

    //Free resolver?
    if (resolver->free_resolver && resolver->cleanup)
        resolver->cleanup(resolver);
}

static void neat_resolver_timeout_cb(uv_timer_t *handle)
{
    struct neat_resolver *resolver = handle->data;
    neat_resolver_cleanup(resolver);
}

static void neat_resolver_dns_sent(uv_udp_send_t *req, int status)
{
    //Callback will be used to send the follow-up request to check for errors
    //printf("UDP send callback\n");
}

static void neat_resolver_dns_alloc_cb(uv_handle_t *handle,
        size_t suggested_size, uv_buf_t *buf)
{
    struct neat_resolver_src_dst_addr *pair = handle->data;

    buf->base = pair->dns_rcv_buf;
    buf->len = sizeof(pair->dns_rcv_buf);
}

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
    struct timeval tv_now;
    uint32_t tdiff;

    if (nread == 0 && addr == NULL) {
        uv_close((uv_handle_t*) &(pair->resolve_handle),
                neat_resolver_close_cb);
        //TODO: Potentially add to remove list already here and start idle cb
        return;
    }

    //This timeout is not the most accurate, since it is affect by how long it
    //takes to process requests that are earlier in the queue. Consider using
    //socket control messages instead (pending OS availability)
    gettimeofday(&tv_now, NULL);
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

    tdiff = ((tv_now.tv_sec - pair->tstamp.tv_sec)*1e3) +
        ((tv_now.tv_usec - pair->tstamp.tv_usec) / 1e3);

    printf("Resolving took %u ms\n", tdiff);

    for (i=0; i<rr_count; i++) {
        rr_record = ldns_rr_list_rr(rr_list, i);
        rdf_result = ldns_rr_rdf(rr_record, 0);
        host_addr = ldns_buffer_new(ldns_rdf_size(rdf_result));

        if (pair->src_addr->family == AF_INET)
            ldns_rdf2buffer_str_a(host_addr, rdf_result);
        else
            ldns_rdf2buffer_str_aaaa(host_addr, rdf_result);

        printf("Resolved to %s\n", ldns_buffer_begin(host_addr));
    
        ldns_buffer_free(host_addr);
    }

    printf("\n");
    ldns_rr_list_deep_free(rr_list);
    ldns_pkt_free(dns_reply);
}

static uint8_t neat_resolver_start_query(struct neat_resolver_src_dst_addr *pair)
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

    fprintf(stdout, "DNS packet length: %zd\n", pair->dns_uv_snd_buf.len);

    if (uv_udp_send(&(pair->dns_snd_handle), &(pair->resolve_handle),
            &(pair->dns_uv_snd_buf), 1,
            (const struct sockaddr*) &(pair->dst_addr.u.generic.addr),
            neat_resolver_dns_sent)) {
        fprintf(stderr, "Failed to start DNS send\n");
        return RETVAL_FAILURE;
    }

    gettimeofday(&(pair->tstamp), NULL);

    return RETVAL_SUCCESS;
}

static uint8_t neat_resolver_create_dst(struct neat_ctx *nc,
        struct neat_resolver_src_dst_addr *pair,
        const char *dst_addr_str)
{
    struct sockaddr_in *dst_addr4;
    struct sockaddr_in6 *dst_addr6;
    void *dst_addr_pton = NULL;
    uint8_t family = pair->src_addr->family;
#ifdef LINUX
    uv_os_fd_t socket_fd = -1;
    char if_name[IF_NAMESIZE];
#endif

    if (family == AF_INET) {
        dst_addr4 = (struct sockaddr_in*) &(pair->dst_addr.u.v4.addr4);
        dst_addr4->sin_family = AF_INET;
        dst_addr4->sin_port = htons(LDNS_PORT);
        dst_addr_pton = &(dst_addr4->sin_addr);
    } else {
        dst_addr6 = (struct sockaddr_in6*) &(pair->dst_addr.u.v6.addr6);
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
        pair->closed = 1;
        fprintf(stderr, "Failure to initialize UDP handle\n");
        return RETVAL_FAILURE;
    }

    pair->resolve_handle.data = pair;

    if (uv_udp_bind(&(pair->resolve_handle),
                (struct sockaddr*) &(pair->src_addr->u.generic.addr),
                UV_UDP_REUSEADDR)) {
        fprintf(stderr, "Failed to bind UDP socket\n");
        uv_close((uv_handle_t*) &(pair->resolve_handle), neat_resolver_close_cb);
        return RETVAL_FAILURE;
    }

    if (uv_udp_recv_start(&(pair->resolve_handle), neat_resolver_dns_alloc_cb,
                neat_resolver_dns_recv_cb)) {
        fprintf(stderr, "Failed to start receiving UDP\n");
        uv_close((uv_handle_t*) &(pair->resolve_handle), neat_resolver_close_cb);
        return RETVAL_FAILURE;
    }

//TODO: Binding to interface name requires sudo, not sure if that is acceptable.
//Ignore any error here for now
#ifdef LINUX
    uv_fileno((uv_handle_t*) &(pair->resolve_handle), &socket_fd);

    if (!if_indextoname(pair->src_addr->if_idx, if_name)) {
        fprintf(stderr, "Could not get interface name for index %u\n",
                pair->src_addr->if_idx);
        return RETVAL_IGNORE;
    }

    if (setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, if_name,
                strlen(if_name)) < 0) {
        fprintf(stderr, "Could not bind socket to interface %s\n", if_name);
        return RETVAL_IGNORE;
    }
#endif

    return RETVAL_SUCCESS;
}

static uint8_t neat_resolver_create_pair(struct neat_resolver *resolver,
        struct neat_addr *src_addr)
{
    const char **dns_addrs = (const char **) ((src_addr->family == AF_INET) ?
            INET_DNS_SERVERS : INET6_DNS_SERVERS);
    uint8_t num_dns = src_addr->family == AF_INET ? sizeof(INET_DNS_SERVERS) :
        sizeof(INET6_DNS_SERVERS);
    uint8_t i;
    struct neat_resolver_src_dst_addr *resolver_pair;

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
        
        if (neat_resolver_create_dst(resolver->nc, resolver_pair,
                    dns_addrs[i]) == RETVAL_FAILURE) {
            fprintf(stderr, "Failed to create resolver pair\n");
            LIST_INSERT_HEAD(&(resolver->resolver_pairs_del), resolver_pair,
                    next_pair);
            //We can't free memory right away, libuv has to be allowed to
            //perform internal clean-up first. This is done after loop is done
            //(uv__run_closing_handles), so we use idle (which is called in the
            //next iteration and before polling)
            if (!uv_is_active((uv_handle_t*) &(resolver->idle_handle)))
                uv_idle_start(&(resolver->idle_handle), neat_resolver_idle_cb);
            continue;
        }

        //Prepare query and mark socket as ready to send

        if (neat_resolver_start_query(resolver_pair)) {
            fprintf(stderr, "Failed to start lookup\n");
            //TODO: Refactor into function, shared with condition above
            LIST_INSERT_HEAD(&(resolver->resolver_pairs_del), resolver_pair,
                    next_pair);
            if (!uv_is_active((uv_handle_t*) &(resolver->idle_handle)))
                uv_idle_start(&(resolver->idle_handle), neat_resolver_idle_cb);
        } else {
            printf("Will lookup %s\n", resolver->domain_name);
            LIST_INSERT_HEAD(&(resolver->resolver_pairs), resolver_pair,
                    next_pair);
        }
    }

    //Start timeout (if not already done)
    if (!uv_is_active((const uv_handle_t *) &(resolver->timeout_handle)))
        uv_timer_start(&(resolver->timeout_handle), neat_resolver_timeout_cb,
                DNS_TIMEOUT, 0);
    
    return RETVAL_SUCCESS;
}

uint8_t neat_getaddrinfo(struct neat_resolver *resolver, uint8_t family,
    const char *service)
{
    struct sockaddr_storage remote_addr;
    struct neat_addr *nsrc_addr = NULL;
    
    resolver->family = family;

    if ((strlen(service) + 1) > MAX_DOMAIN_LENGTH) {
        fprintf(stderr, "Domain name too long\n");
        return RETVAL_FAILURE;
    }

    //TODO: Decide what to do here, when we get an IP address there is no need
    //for lookup. How to deal with addresses, start a timeout right away?
    if (inet_pton(family, service, &remote_addr) == 1) {
        fprintf(stderr, "Service is an IP address or does not match family\n");
        return RETVAL_FAILURE;
    }

    //No need to care about \0, we use calloc ...
    memcpy(resolver->domain_name, service, strlen(service));

    if (!resolver->nc->src_addr_cnt) {
        fprintf(stdout, "No available src addresses\n");
        return RETVAL_SUCCESS;
    }

    //Iterate through src addresses, create udp sockets and start requesting
    for (nsrc_addr = resolver->nc->src_addrs.lh_first; nsrc_addr != NULL;
            nsrc_addr = nsrc_addr->next_addr.le_next) {

        if (resolver->family && nsrc_addr->family != resolver->family)
            continue;

        neat_resolver_create_pair(resolver, nsrc_addr);
    }

    //Iterate through available addresses and start sending DNS queries
    return RETVAL_SUCCESS;
}

uint8_t neat_resolver_init(struct neat_ctx *nc,
                           struct neat_resolver *resolver,
                           void (*cleanup)(struct neat_resolver *resolver))
{
    resolver->nc = nc;
    resolver->cleanup = cleanup;

    resolver->newaddr_cb.event_cb = neat_resolver_handle_newaddr;
    resolver->newaddr_cb.data = resolver;
    resolver->updateaddr_cb.event_cb = neat_resolver_handle_updateaddr;
    resolver->updateaddr_cb.data = resolver;
    resolver->deladdr_cb.event_cb = neat_resolver_handle_deladdr;
    resolver->deladdr_cb.data = resolver;

    if (neat_add_event_cb(nc, NEAT_NEWADDR, &(resolver->newaddr_cb)) ||
        neat_add_event_cb(nc, NEAT_UPDATEADDR, &(resolver->updateaddr_cb)) ||
        neat_add_event_cb(nc, NEAT_DELADDR, &(resolver->deladdr_cb))) {
        fprintf(stderr, "Could not add one or more resolver callbacks\n");
        return RETVAL_FAILURE;
    }

    LIST_INIT(&(resolver->resolver_pairs));
    LIST_INIT(&(resolver->resolver_pairs_del));

    uv_idle_init(nc->loop, &(resolver->idle_handle));
    resolver->idle_handle.data = resolver;
    uv_timer_init(nc->loop, &(resolver->timeout_handle));
    resolver->timeout_handle.data = resolver;

    return RETVAL_SUCCESS;
}

void neat_resolver_cleanup(struct neat_resolver *resolver)
{
    struct neat_resolver_src_dst_addr *resolver_pair, *resolver_itr;

    resolver_itr = resolver->resolver_pairs.lh_first;

    while (resolver_itr != NULL) {
        resolver_pair = resolver_itr;
        resolver_itr = resolver_itr->next_pair.le_next;

        if (uv_is_active((const uv_handle_t*) &(resolver_pair->resolve_handle)))
            uv_close((uv_handle_t*) &(resolver_pair->resolve_handle), neat_resolver_close_cb);

        LIST_REMOVE(resolver_pair, next_pair);
        LIST_INSERT_HEAD(&(resolver->resolver_pairs_del), resolver_pair, next_pair);
    }

    resolver->free_resolver = 1;

    if (uv_is_active((const uv_handle_t*) &(resolver->timeout_handle)))
        uv_timer_stop(&(resolver->timeout_handle));

    //Do cleanup in idle callback
    if (!uv_is_active((const uv_handle_t*) &(resolver->idle_handle)))
        uv_idle_start(&(resolver->idle_handle), neat_resolver_idle_cb);

    //Unsubscribe from callbacks
    neat_remove_event_cb(resolver->nc, NEAT_NEWADDR, &(resolver->newaddr_cb));
    neat_remove_event_cb(resolver->nc, NEAT_UPDATEADDR, &(resolver->updateaddr_cb));
    neat_remove_event_cb(resolver->nc, NEAT_DELADDR, &(resolver->deladdr_cb));
}
