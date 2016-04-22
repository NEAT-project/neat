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
#include "neat_resolver_conf.h"

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

    neat_log(NEAT_LOG_INFO, "%s: Deleted %s", __func__, addr_str);

    neat_resolver_delete_pairs(resolver, src_addr);
}

//libuv-specific callbacks
static void neat_resolver_cleanup_pair(struct neat_resolver_src_dst_addr *pair)
{
    if (pair->dns_snd_buf)
        ldns_buffer_free(pair->dns_snd_buf);

    pair->closed = 1;
}

//This callback is called when we close a UDP socket (handle) and allows us to
//free any allocated resource. In our case, this is only the dns_snd_buf
static void neat_resolver_close_cb(uv_handle_t *handle)
{
    struct neat_resolver_src_dst_addr *resolver_pair = handle->data;
    neat_resolver_cleanup_pair(resolver_pair);
}

static void neat_resolver_flush_pairs_del(struct neat_resolver *resolver)
{
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
}

//This callback is called before libuv polls for I/O and is by default run on
//every iteration. We use it to free memory used by the resolver, and it is only
//active when this is relevant. I.e., we only start the idle handle when
//resolver_pairs_del is not empty
static void neat_resolver_idle_cb(uv_idle_t *handle)
{
    struct neat_resolver *resolver = handle->data;

    neat_resolver_flush_pairs_del(resolver);

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

//Create all results for one match
static uint8_t neat_resolver_fill_results(
        struct neat_resolver *resolver,
        struct neat_resolver_results *result_list,
        struct neat_addr *src_addr,
        struct sockaddr_storage dst_addr)
{
    socklen_t addrlen;
    struct sockaddr_in *addr4;
    struct neat_resolver_res *result;
    uint8_t i;
    uint8_t num_addr_added = 0;

    for (i = 0; i < NEAT_MAX_NUM_PROTO; i++) {
        if (!resolver->ai_protocol[i])
            break;

        result = calloc(sizeof(struct neat_resolver_res), 1);

        if (result == NULL)
            continue;

        addrlen = src_addr->family == AF_INET ?
            sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

        result->ai_family = src_addr->family;
        result->ai_protocol = resolver->ai_protocol[i];
        result->if_idx = src_addr->if_idx;
        result->src_addr = src_addr->u.generic.addr;
        result->src_addr_len = addrlen;
        result->dst_addr = dst_addr;
        result->dst_addr_len = addrlen;
        result->internal = neat_resolver_addr_internal(&dst_addr);

        //Code can't get here without having passed through sanitizing function
        switch (result->ai_protocol) {
        case IPPROTO_UDP:
#ifdef IPPROTO_UDPLITE
        case IPPROTO_UDPLITE:
#endif
            result->ai_socktype = SOCK_DGRAM;
            break;
        default:
            result->ai_socktype = SOCK_STREAM;
            break;
        }

        //Head of sockaddr_in and sockaddr_in6 is the same, so this is safe
        //for setting port
        addr4 = (struct sockaddr_in*) &(result->dst_addr);
        addr4->sin_port = resolver->dst_port;

        LIST_INSERT_HEAD(result_list, result, next_res);
        num_addr_added++;
    }

    return num_addr_added;
}

//This timeout is used when we "resolve" a literal. It works slightly different
//than the normal resolver timeout function. We just iterate through source
//addresses can create a result structure for those that match
static void neat_resolver_literal_timeout_cb(uv_timer_t *handle)
{
    struct neat_resolver *resolver = handle->data;
    struct neat_resolver_results *result_list;
    uint32_t num_resolved_addrs = 0;
    struct neat_addr *nsrc_addr = NULL;
    void *dst_addr_pton = NULL;
    struct sockaddr_storage dst_addr;
    union {
        struct sockaddr_in *dst_addr4;
        struct sockaddr_in6 *dst_addr6;
    } u;

    //There were no addresses available, so return error
    //TODO: Consider adding a different error
    if (!resolver->nc->src_addr_cnt) {
        resolver->handle_resolve(resolver, NULL, NEAT_RESOLVER_ERROR);
        return;
    }

    //Signal internal error
    if ((result_list =
                calloc(sizeof(struct neat_resolver_results), 1)) == NULL) {
        resolver->handle_resolve(resolver, NULL, NEAT_RESOLVER_ERROR);
        return;
    }

    if (resolver->family == AF_INET) {
        u.dst_addr4 = (struct sockaddr_in*) &dst_addr;
#ifdef HAVE_SIN_LEN
        u.dst_addr4->sin_len = sizeof(struct sockaddr_in);
#endif
        u.dst_addr4->sin_family = AF_INET;
        u.dst_addr4->sin_port = resolver->dst_port;
        dst_addr_pton = &(u.dst_addr4->sin_addr);
    } else {
        u.dst_addr6 = (struct sockaddr_in6*) &dst_addr;
#ifdef HAVE_SIN6_LEN
        u.dst_addr6->sin6_len = sizeof(struct sockaddr_in6);
#endif
        u.dst_addr6->sin6_family = AF_INET6;
        u.dst_addr6->sin6_port = resolver->dst_port;
        dst_addr_pton = &(u.dst_addr6->sin6_addr);

    }

    //We already know that this will be successful, it was checked in the
    //literal-check performed earlier
    inet_pton(resolver->family, resolver->domain_name, dst_addr_pton);

    LIST_INIT(result_list);

    for (nsrc_addr = resolver->nc->src_addrs.lh_first; nsrc_addr != NULL;
            nsrc_addr = nsrc_addr->next_addr.le_next) {
        //Family is always set for literals
        if (nsrc_addr->family != resolver->family)
            continue;

        //Do not use deprecated addresses
        if (nsrc_addr->family == AF_INET6 && !nsrc_addr->u.v6.ifa_pref)
            continue;

        num_resolved_addrs += neat_resolver_fill_results(resolver, result_list,
                nsrc_addr, dst_addr);
    }

    if (!num_resolved_addrs)
        resolver->handle_resolve(resolver, NULL, NEAT_RESOLVER_ERROR);
    else
        resolver->handle_resolve(resolver, result_list, NEAT_RESOLVER_OK);
}

//Called when timeout expires. This function will pass the results of the DNS
//query to the application using NEAT
static void neat_resolver_timeout_cb(uv_timer_t *handle)
{
    struct neat_resolver *resolver = handle->data;
    struct neat_resolver_src_dst_addr *pair_itr = NULL;
    struct neat_resolver_results *result_list;
    uint32_t num_resolved_addrs = 0;
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
        //Resolve has not been completed
        if (!pair_itr->resolved_addr[0].ss_family) {
            pair_itr = pair_itr->next_pair.le_next;
            continue;
        }

        for (i = 0; i < MAX_NUM_RESOLVED; i++) {
            //Resolved addresses are added linearly, so if this is empty then
            //that is the end of result list
            if (!pair_itr->resolved_addr[i].ss_family)
                break;

            if (pair_itr->src_addr->family == AF_INET6 &&
                !pair_itr->src_addr->u.v6.ifa_pref)
                return;

            num_resolved_addrs += neat_resolver_fill_results(resolver,
                    result_list, pair_itr->src_addr,
                    pair_itr->resolved_addr[i]);
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

    if (uv_is_active((uv_handle_t*) &(pair->resolve_handle))) {
        uv_udp_recv_stop(&(pair->resolve_handle));
        uv_close((uv_handle_t*) &(pair->resolve_handle), neat_resolver_close_cb);
    }

    if (pair->next_pair.le_next != NULL || pair->next_pair.le_prev != NULL)
        LIST_REMOVE(pair, next_pair);

    LIST_INSERT_HEAD(&(resolver->resolver_pairs_del), pair,
            next_pair);

    //We can't free memory right away, libuv has to be allowed to
    //perform internal clean-up first. This is done after loop is done
    //(uv__run_closing_handles), so we use idle (which is called in the
    //next iteration and before polling)
    if (uv_backend_fd(resolver->nc->loop) != -1 &&
        !uv_is_active((uv_handle_t*) &(resolver->idle_handle)))
        uv_idle_start(&(resolver->idle_handle), neat_resolver_idle_cb);
}

static uint8_t neat_resolver_check_duplicate(
        struct neat_resolver_src_dst_addr *pair, const char *resolved_addr_str)
{
    //Accepts a src_dst_pair and an address, convert this address to struct
    //in{6}_addr, then check all pairs if this IP has seen before for same
    //(index, source)
    struct neat_addr *src_addr = pair->src_addr;
    struct sockaddr_in *src_addr_4 = NULL, *cmp_addr_4 = NULL;
    struct sockaddr_in6 *src_addr_6 = NULL, *cmp_addr_6 = NULL;
    union {
        struct in_addr resolved_addr_4;
        struct in6_addr resolved_addr_6;
    } u;
    struct neat_resolver_src_dst_addr *itr;
    uint8_t addr_equal = 0;
    int32_t i;

    if (src_addr->family == AF_INET) {
        src_addr_4 = &(src_addr->u.v4.addr4);
        i = inet_pton(AF_INET, resolved_addr_str,
                (void *) &u.resolved_addr_4);
    } else {
        src_addr_6 = &(src_addr->u.v6.addr6);
        i = inet_pton(AF_INET6, resolved_addr_str,
                (void *) &u.resolved_addr_6);
    }

    //the calleee also does pton, so that failure will currently be handled
    //elsewhere
    //TODO: SO UGLY!!!!!!!!!!!!!
    if (i <= 0)
        return 0;

    for (itr = pair->resolver->resolver_pairs.lh_first; itr != NULL;
            itr = itr->next_pair.le_next) {
        addr_equal = 0;

        //Must match index
        if (src_addr->if_idx != itr->src_addr->if_idx ||
            src_addr->family != itr->src_addr->family)
            continue;

        if (src_addr->family == AF_INET) {
            cmp_addr_4 = &(itr->src_addr->u.v4.addr4);
            addr_equal = (cmp_addr_4->sin_addr.s_addr ==
                          src_addr_4->sin_addr.s_addr);
        } else {
            cmp_addr_6 = &(itr->src_addr->u.v6.addr6);
            addr_equal = neat_addr_cmp_ip6_addr(cmp_addr_6->sin6_addr,
                                                src_addr_6->sin6_addr);
        }

        if (!addr_equal)
            continue;

        //Check all resolved addresses
        for (i = 0; i < MAX_NUM_RESOLVED; i++) {
            if (!itr->resolved_addr[i].ss_family)
                break;

            if (src_addr->family == AF_INET) {
                cmp_addr_4 = (struct sockaddr_in*) &(itr->resolved_addr[i]);
                addr_equal = (u.resolved_addr_4.s_addr ==
                              cmp_addr_4->sin_addr.s_addr);
            } else {
                cmp_addr_6 = (struct sockaddr_in6*) &(itr->resolved_addr[i]);
                addr_equal = neat_addr_cmp_ip6_addr(cmp_addr_6->sin6_addr,
                                                    u.resolved_addr_6);
            }

            if (addr_equal)
                return 1;
        }
    }

    return 0;
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

            if (neat_resolver_check_duplicate(pair,
                    (const char *) ldns_buffer_begin(host_addr))) {
                ldns_buffer_free(host_addr);
                continue;
            }

            addr4 = (struct sockaddr_in*) &(pair->resolved_addr[num_resolved]);

            if (!inet_pton(AF_INET, (const char*) ldns_buffer_begin(host_addr),
                    &(addr4->sin_addr)))
                pton_failed = 1;
            else
                addr4->sin_family = AF_INET;
        } else {
            ldns_rdf2buffer_str_aaaa(host_addr, rdf_result);
            if (neat_resolver_check_duplicate(pair,
                    (const char *) ldns_buffer_begin(host_addr))) {
                ldns_buffer_free(host_addr);
                continue;
            }

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
        neat_log(NEAT_LOG_ERROR, "%s - Could not create DNS packet", __func__);
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
        neat_log(NEAT_LOG_ERROR, "%s - Could not convert pkt to buf", __func__);
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
        neat_log(NEAT_LOG_ERROR, "%s - Failed to start DNS send", __func__);
        return RETVAL_FAILURE;
    }

    return RETVAL_SUCCESS;
}

//Create one SRC/DST DNS resolver pair. Pair has already been allocated
static uint8_t neat_resolver_create_pair(struct neat_ctx *nc,
        struct neat_resolver_src_dst_addr *pair,
        const struct sockaddr_storage *server_addr)
{
    struct sockaddr_in *dst_addr4, *server_addr4;
    struct sockaddr_in6 *dst_addr6, *server_addr6;
    uint8_t family = pair->src_addr->family;
#ifdef __linux__
    uv_os_fd_t socket_fd = -1;
    char if_name[IF_NAMESIZE];
#endif

    if (family == AF_INET) {
        server_addr4 = (struct sockaddr_in*) server_addr;
        dst_addr4 = &(pair->dst_addr.u.v4.addr4);
        dst_addr4->sin_family = AF_INET;
        dst_addr4->sin_port = htons(LDNS_PORT);
        dst_addr4->sin_addr = server_addr4->sin_addr;
    } else {
        server_addr6 = (struct sockaddr_in6*) server_addr;
        dst_addr6 = &(pair->dst_addr.u.v6.addr6);
        dst_addr6->sin6_family = AF_INET6;
        dst_addr6->sin6_port = htons(LDNS_PORT);
        dst_addr6->sin6_addr = server_addr6->sin6_addr;
    }

    //Configure uv_udp_handle
    if (uv_udp_init(nc->loop, &(pair->resolve_handle))) {
        //Closed is normally set in close_cb, but since we will never get that
        //far, set it here instead
        //pair->closed = 1;
        neat_log(NEAT_LOG_ERROR, "%s - Failure to initialize UDP handle", __func__);
        return RETVAL_FAILURE;
    }

    pair->resolve_handle.data = pair;

    if (uv_udp_bind(&(pair->resolve_handle),
                (struct sockaddr*) &(pair->src_addr->u.generic.addr),
                0)) {
        neat_log(NEAT_LOG_ERROR, "%s - Failed to bind UDP socket", __func__);
        return RETVAL_FAILURE;
    }

    if (uv_udp_recv_start(&(pair->resolve_handle), neat_resolver_dns_alloc_cb,
                neat_resolver_dns_recv_cb)) {
        neat_log(NEAT_LOG_ERROR, "%s - Failed to start receiving UDP", __func__);
        return RETVAL_FAILURE;
    }

//TODO: Binding to interface name requires sudo, not sure if that is acceptable.
//Ignore any error here for now
#ifdef __linux__
    uv_fileno((uv_handle_t*) &(pair->resolve_handle), &socket_fd);

    if (!if_indextoname(pair->src_addr->if_idx, if_name)) {
        /*neat_log(NEAT_LOG_ERROR, "%s - Could not get interface name for index %u",
                __func__, pair->src_addr->if_idx);*/
        return RETVAL_IGNORE;
    }

    if (setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, if_name,
                strlen(if_name)) < 0) {
        /*neat_log(NEAT_LOG_ERROR, "%s - Could not bind socket to interface %s\n",
        __func__, if_name); */
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
    struct neat_resolver_src_dst_addr *resolver_pair;
    struct neat_resolver_server *server_itr;

    //After adding support for restart, we can end up here without a domain
    //name. There is not point continuing if we have no domain name to resolve
    if (!resolver->domain_name[0])
        return RETVAL_SUCCESS;

    for (server_itr = resolver->server_list.lh_first; server_itr != NULL;
            server_itr = server_itr->next_server.le_next) {

        if (src_addr->family != server_itr->server_addr.ss_family)
            continue;

        resolver_pair = (struct neat_resolver_src_dst_addr*)
            calloc(sizeof(struct neat_resolver_src_dst_addr), 1);

        if (!resolver_pair) {
            neat_log(NEAT_LOG_ERROR, "%s - Failed to allocate memory for resolver pair", __func__);
            continue;
        }

        resolver_pair->resolver = resolver;
        resolver_pair->src_addr = src_addr;

        if (neat_resolver_create_pair(resolver->nc, resolver_pair,
                    &(server_itr->server_addr)) == RETVAL_FAILURE) {
            neat_log(NEAT_LOG_ERROR, "%s - Failed to create resolver pair", __func__);
            neat_resolver_mark_pair_del(resolver_pair);
            continue;
        }

        if (neat_resolver_send_query(resolver_pair)) {
            neat_log(NEAT_LOG_ERROR, "%s - Failed to start lookup", __func__);
            neat_resolver_mark_pair_del(resolver_pair);
        } else {
            //printf("Will lookup %s\n", resolver->domain_name);
            LIST_INSERT_HEAD(&(resolver->resolver_pairs), resolver_pair,
                    next_pair);
        }
    }

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
static int8_t neat_resolver_check_for_literal(uint8_t *family, const char *node)
{
    struct in6_addr dummy_addr;
    int32_t v4_literal = 0, v6_literal = 0;

    if (*family != AF_UNSPEC && *family != AF_INET && *family != AF_INET6) {
        neat_log(NEAT_LOG_ERROR, "%s - Unsupported address family", __func__);
        return -1;
    }

    //The only time inet_pton fails is if the system lacks v4/v6 support. This
    //should rather be handled with an ifdef + check at compile time
    v4_literal = inet_pton(AF_INET, node, &dummy_addr);
    v6_literal = inet_pton(AF_INET6, node, &dummy_addr);

    //These are the two possible error cases:
    //if family is v4 and address is v6 (or opposite), then user has made a
    //mistake and must be notifed
    if ((*family == AF_INET && v6_literal) ||
        (*family == AF_INET6 && v4_literal)) {
        neat_log(NEAT_LOG_ERROR, "%s - Mismatch between family and literal", __func__);
        return -1;
    }
    if (*family == AF_UNSPEC) {
        if (v4_literal)
            *family = AF_INET;
        if (v6_literal)
            *family = AF_INET6;
    }
    return v4_literal | v6_literal;
}

static uint8_t neat_validate_protocols(int protocols[], uint8_t proto_count)
{
    uint8_t i;

    if (proto_count > NEAT_MAX_NUM_PROTO)
        return RETVAL_FAILURE;

    for (i = 0; i < proto_count; i++) {
        switch (protocols[i]) {
        case IPPROTO_UDP:
#ifdef IPPROTO_UDPLITE
        case IPPROTO_UDPLITE:
#endif
        case IPPROTO_TCP:
#ifdef IPPROTO_SCTP
        case IPPROTO_SCTP:
#endif
            continue;
        default:
            return RETVAL_FAILURE;
        }
    }

    return RETVAL_SUCCESS;
}

//Public NEAT resolver functions
//getaddrinfo starts a query for the provided service
uint8_t neat_getaddrinfo(struct neat_resolver *resolver, uint8_t family,
        const char *node, const char *service, int ai_protocol[],
        uint8_t proto_count)
{
    struct neat_addr *nsrc_addr = NULL;
    int32_t dst_port = 0;
    int8_t retval;
    uint8_t i;

    dst_port = atoi(service);

    if (dst_port <= 0 || dst_port > UINT16_MAX) {
        neat_log(NEAT_LOG_ERROR, "%s - Invalid service specified", __func__);
        return RETVAL_FAILURE;
    }

    if (family && family != AF_INET && family != AF_INET6 && family != AF_UNSPEC) {
        neat_log(NEAT_LOG_ERROR, "%s - Invalid family specified", __func__);
        return RETVAL_FAILURE;
    }

    if (neat_validate_protocols(ai_protocol, proto_count)) {
        neat_log(NEAT_LOG_ERROR, "%s - Error in desired protocol list", __func__);
        return RETVAL_FAILURE;
    }

    for (i = 0; i < proto_count; i++)
        resolver->ai_protocol[i] = ai_protocol[i];

    resolver->family = family;
    resolver->dst_port = htons(dst_port);

    if ((strlen(node) + 1) > MAX_DOMAIN_LENGTH) {
        neat_log(NEAT_LOG_ERROR, "%s - Domain name too long", __func__);
        return RETVAL_FAILURE;
    }

    retval = neat_resolver_check_for_literal(&resolver->family, node);

    if (retval < 0)
        return RETVAL_FAILURE;

    //No need to care about \0, we use calloc ...
    memcpy(resolver->domain_name, node, strlen(node));

    //node is a literal, so we will just wait a short while for address list to
    //be populated
    if (retval) {
        uv_timer_start(&(resolver->timeout_handle),
                neat_resolver_literal_timeout_cb,
                DNS_LITERAL_TIMEOUT, 0);
        return RETVAL_SUCCESS;
    }

    //Start the resolver timeout, this includes fetching addresses
    uv_timer_start(&(resolver->timeout_handle), neat_resolver_timeout_cb,
            resolver->dns_t1, 0);

    //No point starting to query if we don't have any source addresses
    if (!resolver->nc->src_addr_cnt) {
        neat_log(NEAT_LOG_ERROR, "%s - No available src addresses", __func__);
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

        //TODO: Potential place to filter based on policy

        neat_resolver_create_pairs(resolver, nsrc_addr);
    }

    //Iterate through available addresses and start sending DNS queries
    return RETVAL_SUCCESS;
}

//Initialize the resolver. Set up callbacks etc.
struct neat_resolver *
neat_resolver_init(struct neat_ctx *nc,
                   const char *resolv_conf_path,
                   neat_resolver_handle_t handle_resolve,
                   neat_resolver_cleanup_t cleanup)
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
        neat_log(NEAT_LOG_ERROR, "%s - Could not add one or more resolver callbacks", __func__);
        return NULL;
    }

    LIST_INIT(&(resolver->resolver_pairs));
    LIST_INIT(&(resolver->resolver_pairs_del));

    uv_idle_init(nc->loop, &(resolver->idle_handle));
    resolver->idle_handle.data = resolver;
    uv_timer_init(nc->loop, &(resolver->timeout_handle));
    resolver->timeout_handle.data = resolver;

    if (uv_fs_event_init(nc->loop, &(resolver->resolv_conf_handle))) {
        neat_log(NEAT_LOG_ERROR, "%s - Could not initialize fs event handle", __func__);
        return NULL;
    }

    resolver->resolv_conf_handle.data = resolver;

    if (uv_fs_event_start(&(resolver->resolv_conf_handle),
                      neat_resolver_resolv_conf_updated,
                      resolv_conf_path, 0)) {
        neat_log(NEAT_LOG_ERROR, "%s - Could not start fs event handle", __func__);
        return NULL;
    }

    if (!neat_resolver_add_initial_servers(resolver))
        return NULL;

    return resolver;
}

//Helper function used by both cleanup and reset
static void neat_resolver_cleanup(struct neat_resolver *resolver, uint8_t free_mem)
{
    struct neat_resolver_src_dst_addr *resolver_pair, *resolver_itr;
    struct neat_resolver_server *server;

    resolver_itr = resolver->resolver_pairs.lh_first;

    while (resolver_itr != NULL) {
        resolver_pair = resolver_itr;
        resolver_itr = resolver_itr->next_pair.le_next;
        neat_resolver_mark_pair_del(resolver_pair);

        //If loop is stopped, we need to clean up (i.e., free dns buffer)
        //manually since close_cb will never be called
        if (uv_backend_fd(resolver->nc->loop) == -1)
            neat_resolver_cleanup_pair(resolver_pair);
    }

    resolver->free_resolver = free_mem;
    resolver->name_resolved_timeout = 0;

    if (uv_is_active((const uv_handle_t*) &(resolver->timeout_handle)))
        uv_timer_stop(&(resolver->timeout_handle));

    //We need to do this here, in addition to in mark_pair_del, since we might
    //get in the situation where there are zero addresses to delete (for example
    //if resolver is freed before there are no source addresses)
    //TODO: Not sure if backend_fd is the best way to check if loop is closed,
    //but it is what I found now. Improve later. alive() seems to always return
    //true, for some reason. Will debug more later
    if (uv_backend_fd(resolver->nc->loop) != -1 &&
        !uv_is_active((const uv_handle_t*) &(resolver->idle_handle)))
        uv_idle_start(&(resolver->idle_handle), neat_resolver_idle_cb);

    //Unsubscribe from callbacks if we are going to release memory
    if (free_mem) {
        neat_remove_event_cb(resolver->nc, NEAT_NEWADDR, &(resolver->newaddr_cb));
        neat_remove_event_cb(resolver->nc, NEAT_DELADDR, &(resolver->deladdr_cb));
        uv_fs_event_stop(&(resolver->resolv_conf_handle));

        //Remove all entries in the server table
        while (resolver->server_list.lh_first != NULL) {
            server = resolver->server_list.lh_first;
            LIST_REMOVE(resolver->server_list.lh_first, next_server);
            free(server);
        }
    } else {
        memset(resolver->domain_name, 0, MAX_DOMAIN_LENGTH);
    }


    memset(resolver->ai_protocol, 0, sizeof(resolver->ai_protocol));
}

void neat_resolver_reset(struct neat_resolver *resolver)
{
    neat_resolver_cleanup(resolver, 0);
}

void neat_resolver_release(struct neat_resolver *resolver)
{
    neat_resolver_cleanup(resolver, 1);

    //If loop is not stopped, return. Otherwise, the idle callback will never be
    //called, so we have to manually free the pairs
    if (uv_backend_fd(resolver->nc->loop) != -1)
        return;

    neat_resolver_flush_pairs_del(resolver);
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
