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
#include "neat_resolver_helpers.h"

static uint8_t neat_resolver_create_pairs(struct neat_addr *src_addr,
                                          struct neat_resolver_request *request);
static void neat_resolver_delete_pairs(struct neat_resolver_request *request,
                                       struct neat_addr *addr_to_delete);

static void neat_resolver_mark_pair_del(struct neat_resolver *resolver,
                                        struct neat_resolver_src_dst_addr *pair);

//NEAT internal callbacks, not very interesting
static void neat_resolver_handle_newaddr(struct neat_ctx *nc,
                                         void *p_ptr,
                                         void *data)
{
    struct neat_resolver *resolver = p_ptr;
    struct neat_resolver_request *request_itr;
    struct neat_addr *src_addr = data;

    //Ignore addresses that are deprecated
    if (src_addr->family == AF_INET6 && !src_addr->u.v6.ifa_pref)
        return;

    request_itr = resolver->request_queue.tqh_first;

    while (request_itr != NULL) {
        if (request_itr->family && request_itr->family != src_addr->family) {
            request_itr = request_itr->next_req.tqe_next;
            continue;
        }

        neat_resolver_create_pairs(src_addr, request_itr);
        request_itr = request_itr->next_req.tqe_next;
    }
}

static void neat_resolver_handle_deladdr(struct neat_ctx *nic,
                                         void *p_ptr,
                                         void *data)
{
    struct neat_resolver *resolver = p_ptr;
    struct neat_resolver_request *request_itr;
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

    request_itr = resolver->request_queue.tqh_first;

    while (request_itr != NULL) {
        neat_resolver_delete_pairs(request_itr, src_addr);
        request_itr = request_itr->next_req.tqe_next;
    }

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

static void neat_resolver_close_timer(uv_handle_t *handle)
{
    struct neat_resolver_request *request = handle->data;
    TAILQ_REMOVE(&(request->resolver->dead_request_queue), request,
                 next_dead_req);
    free(request);
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
        //TODO: Instead of free, consider making a resolve_pair cache
        free(resolver_pair);
    }
}

static void neat_resolver_idle_close_cb(uv_handle_t *handle)
{
    struct neat_resolver *resolver = handle->data;
    free(resolver);
}

//This callback is called before libuv polls for I/O and is by default run on
//every iteration. We use it to free memory used by the resolver, and it is only
//active when this is relevant. I.e., we only start the idle handle when
//resolver_pairs_del is not empty
static void neat_resolver_idle_cb(uv_idle_t *handle)
{
    struct neat_resolver *resolver = handle->data;
    struct neat_resolver_request *request_itr, *request_tmp;

    neat_resolver_flush_pairs_del(resolver);

    //We cant stop idle until all pairs marked for deletion have been removed
    if (resolver->resolver_pairs_del.lh_first)
        return;

    //idle is also both when we clean up one request and when we clean up the
    //whole resolver, we need to guard against this
    if (!resolver->free_resolver) {
        uv_idle_stop(&(resolver->idle_handle));
        return;
    }

    //Free all dead requests
    for (request_itr = resolver->dead_request_queue.tqh_first;
         request_itr != NULL;) {
        request_tmp = request_itr;
        request_itr = request_itr->next_req.tqe_next;

        //No need to remove from list. resolver can't be used after this
        //function is called
        free(request_tmp);
    }

    if (!resolver->fs_event_closed)
        return;

    uv_idle_stop(&(resolver->idle_handle));
    uv_close((uv_handle_t*) handle, neat_resolver_idle_close_cb);
}

static void neat_resolver_request_cleanup(struct neat_resolver_request *request)
{
    struct neat_resolver_src_dst_addr *resolver_pair, *resolver_itr;

    resolver_itr = request->resolver_pairs.lh_first;

    while (resolver_itr != NULL) {
        resolver_pair = resolver_itr;
        resolver_itr = resolver_itr->next_pair.le_next;
        neat_resolver_mark_pair_del(request->resolver, resolver_pair);

        //If loop is stopped, we need to clean up (i.e., free dns buffer)
        //manually since close_cb will never be called
        if (uv_backend_fd(request->resolver->nc->loop) == -1)
            neat_resolver_cleanup_pair(resolver_pair);
    }

    if (uv_is_active((const uv_handle_t*) &(request->timeout_handle)))
        uv_timer_stop(&(request->timeout_handle));

    //Move to dead requests list
    TAILQ_REMOVE(&(request->resolver->request_queue), request, next_req);
    request->next_req.tqe_next = NULL;
    request->next_req.tqe_prev = NULL;
    TAILQ_INSERT_HEAD(&(request->resolver->dead_request_queue), request,
                      next_dead_req);

    //Timers need to, like file descriptors, be closed async. Thus, freeing the
    //request must be deferred until timer has been closed. No need to use idle
    //etc. here. The callback will always be run.
    uv_close((uv_handle_t*) &(request->timeout_handle),
             neat_resolver_close_timer);
}

static uint32_t neat_resolver_literal_populate_results(struct neat_resolver_request *request,
                                                       struct neat_resolver_results *result_list)
{
    uint32_t num_resolved_addrs = 0;
    struct neat_addr *nsrc_addr = NULL;
    void *dst_addr_pton = NULL;
    struct sockaddr_storage dst_addr;
    union {
        struct sockaddr_in *dst_addr4;
        struct sockaddr_in6 *dst_addr6;
    } u;

    if (request->family == AF_INET) {
        u.dst_addr4 = (struct sockaddr_in*) &dst_addr;
        memset(u.dst_addr4, 0, sizeof(struct sockaddr_in));
        u.dst_addr4->sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
        u.dst_addr4->sin_len = sizeof(struct sockaddr_in);
#endif
        dst_addr_pton = &(u.dst_addr4->sin_addr);
    } else {
        u.dst_addr6 = (struct sockaddr_in6*) &dst_addr;
        memset(u.dst_addr6, 0, sizeof(struct sockaddr_in6));
        u.dst_addr6->sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
        u.dst_addr6->sin6_len = sizeof(struct sockaddr_in6);
#endif
        dst_addr_pton = &(u.dst_addr6->sin6_addr);

    }

    //We already know that this will be successful, it was checked in the
    //literal-check performed earlier
    inet_pton(request->family, request->domain_name, dst_addr_pton);

    for (nsrc_addr = request->resolver->nc->src_addrs.lh_first;
         nsrc_addr != NULL; nsrc_addr = nsrc_addr->next_addr.le_next) {
        //Family is always set for literals
        if (nsrc_addr->family != request->family)
            continue;

        //Do not use deprecated addresses
        if (nsrc_addr->family == AF_INET6 && !nsrc_addr->u.v6.ifa_pref)
            continue;

        num_resolved_addrs += neat_resolver_helpers_fill_results(request,
                                                                 result_list,
                                                                 nsrc_addr,
                                                                 dst_addr);
    }

    return num_resolved_addrs;
}

static uint32_t neat_resolver_populate_results(struct neat_resolver_request *request,
                                               struct neat_resolver_results *result_list)
{
    struct neat_resolver_src_dst_addr *pair_itr = NULL;
    uint32_t num_resolved_addrs = 0;
    uint8_t i;

    pair_itr = request->resolver_pairs.lh_first;

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
                break;

            //TODO: Consider connecting pairs to request instead of resolver
            num_resolved_addrs += neat_resolver_helpers_fill_results(request,
                                                                     result_list,
                                                                     pair_itr->src_addr,
                                                                     pair_itr->resolved_addr[i]);
        }

        pair_itr = pair_itr->next_pair.le_next;
    }

    return num_resolved_addrs;
}

static void neat_resolver_timeout_shared(uv_timer_t *handle,
                                         uint8_t literal)
{
    struct neat_resolver_request *request = handle->data;
    struct neat_resolver_results *result_list;
    uint32_t num_resolved_addrs = 0;

    //If resolver is marked for deletion, then ignore any new replies
    if (request->resolver->free_resolver)
        return;

    //DNS timeout, call DNS callback with timeout error code
    if (!literal && !request->name_resolved_timeout) {
        request->resolve_cb(NULL, NEAT_RESOLVER_TIMEOUT, request->user_data);
        neat_resolver_request_cleanup(request);
        return;
    }

    //There were no addresses available, so return error
    //TODO: Consider adding a different error
    if (literal && !request->resolver->nc->src_addr_cnt) {
        request->resolve_cb(NULL, NEAT_RESOLVER_ERROR, request->user_data);
        neat_resolver_request_cleanup(request);
        return;
    }

    //Signal internal error
    if ((result_list =
                calloc(sizeof(struct neat_resolver_results), 1)) == NULL) {
        request->resolve_cb(NULL, NEAT_RESOLVER_ERROR, request->user_data);
        neat_resolver_request_cleanup(request);
        return;
    }

    LIST_INIT(result_list);

    if (literal) {
        num_resolved_addrs = neat_resolver_literal_populate_results(request,
                                                                    result_list);
    } else {
        num_resolved_addrs = neat_resolver_populate_results(request,
                                                            result_list);
    }

    if (!num_resolved_addrs) {
        request->resolve_cb(NULL, NEAT_RESOLVER_ERROR, request->user_data);
        free(result_list);
    } else {
        request->resolve_cb(result_list, NEAT_RESOLVER_OK, request->user_data);
    }

    //This guard is good enough for now. The only case where a request can be
    //freed (or marked for free) when we get here, is if resolver has been
    //released
    if (!request->resolver->free_resolver) {
        neat_resolver_request_cleanup(request);
    }
}

//This timeout is used when we "resolve" a literal. It works slightly different
//than the normal resolver timeout function. We just iterate through source
//addresses can create a result structure for those that match
static void neat_resolver_literal_timeout_cb(uv_timer_t *handle)
{
    neat_resolver_timeout_shared(handle, 1);
}

//Called when timeout expires. This function will pass the results of the DNS
//query to the application using NEAT
static void neat_resolver_timeout_cb(uv_timer_t *handle)
{
    neat_resolver_timeout_shared(handle, 0);
}

//Called when a DNS request has been (i.e., passed to socket). We will send the
//second query (used for checking poisoning) here. If that is needed
static void neat_resolver_dns_sent_cb(uv_udp_send_t *req, int status)
{
    //Callback will be used to send the follow-up request to check for errors
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
static void neat_resolver_mark_pair_del(struct neat_resolver *resolver,
                                        struct neat_resolver_src_dst_addr *pair)
{
    if (uv_is_active((uv_handle_t*) &(pair->resolve_handle))) {
        uv_udp_recv_stop(&(pair->resolve_handle));
        uv_close((uv_handle_t*) &(pair->resolve_handle), neat_resolver_close_cb);
    }

    if (pair->next_pair.le_next != NULL || pair->next_pair.le_prev != NULL) {
        LIST_REMOVE(pair, next_pair);
        pair->next_pair.le_next = NULL;
        pair->next_pair.le_prev = NULL;
    }

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

        if (!host_addr)
            continue;

        if (pair->src_addr->family == AF_INET) {
            ldns_rdf2buffer_str_a(host_addr, rdf_result);

            if (neat_resolver_helpers_check_duplicate(pair,
                    (const char *) ldns_buffer_begin(host_addr))) {
                ldns_buffer_free(host_addr);
                continue;
            }

            addr4 = (struct sockaddr_in*) &(pair->resolved_addr[num_resolved]);

            if (!inet_pton(AF_INET, (const char*) ldns_buffer_begin(host_addr),
                    &(addr4->sin_addr))) {
                pton_failed = 1;
            } else {
                addr4->sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
                addr4->sin_len = sizeof(struct sockaddr_in);
#endif
            }
        } else {
            ldns_rdf2buffer_str_aaaa(host_addr, rdf_result);
            if (neat_resolver_helpers_check_duplicate(pair,
                    (const char *) ldns_buffer_begin(host_addr))) {
                ldns_buffer_free(host_addr);
                continue;
            }

            addr6 = (struct sockaddr_in6*) &(pair->resolved_addr[num_resolved]);

            if (!inet_pton(AF_INET6, (const char*) ldns_buffer_begin(host_addr),
                    &(addr6->sin6_addr))) {
                pton_failed = 1;
            } else {
                addr6->sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
                addr6->sin6_len = sizeof(struct sockaddr_in6);
#endif
            }
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

    if (num_resolved && !pair->request->name_resolved_timeout){
        uv_timer_stop(&(pair->request->timeout_handle));
        uv_timer_start(&(pair->request->timeout_handle), neat_resolver_timeout_cb,
                pair->request->resolver->dns_t2, 0);
        pair->request->name_resolved_timeout = 1;
    }
}

//Prepare and send (or, start sending) a DNS query for the given service
static uint8_t neat_resolver_send_query(struct neat_resolver_src_dst_addr *pair,
                                        struct neat_resolver_request *request)
{
    ldns_pkt *pkt;
    ldns_rr_type rr_type;

    if (pair->src_addr->family == AF_INET)
        rr_type = LDNS_RR_TYPE_A;
    else
        rr_type = LDNS_RR_TYPE_AAAA;

    //Create a DNS query for aUrl
    if (ldns_pkt_query_new_frm_str(&pkt, request->domain_name, rr_type,
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

    neat_log(NEAT_LOG_DEBUG, "%s - Request for %s sent", __func__,
             request->domain_name);

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
#ifdef HAVE_SIN_LEN
        dst_addr4->sin_len = sizeof(struct sockaddr_in);
#endif
    } else {
        server_addr6 = (struct sockaddr_in6*) server_addr;
        dst_addr6 = &(pair->dst_addr.u.v6.addr6);
        dst_addr6->sin6_family = AF_INET6;
        dst_addr6->sin6_port = htons(LDNS_PORT);
        dst_addr6->sin6_addr = server_addr6->sin6_addr;
#ifdef HAVE_SIN6_LEN
        dst_addr6->sin6_len = sizeof(struct sockaddr_in6);
#endif
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
static uint8_t neat_resolver_create_pairs(struct neat_addr *src_addr,
                                          struct neat_resolver_request *request)
{
    struct neat_resolver_src_dst_addr *resolver_pair;
    struct neat_resolver_server *server_itr;

    //After adding support for restart, we can end up here without a domain
    //name. There is not point continuing if we have no domain name to resolve
    if (!request->domain_name[0])
        return RETVAL_SUCCESS;

    for (server_itr = request->resolver->server_list.lh_first;
         server_itr != NULL; server_itr = server_itr->next_server.le_next) {

        if (src_addr->family != server_itr->server_addr.ss_family)
            continue;

        resolver_pair = (struct neat_resolver_src_dst_addr*)
            calloc(sizeof(struct neat_resolver_src_dst_addr), 1);

        if (!resolver_pair) {
            neat_log(NEAT_LOG_ERROR, "%s - Failed to allocate memory for resolver pair", __func__);
            continue;
        }

        resolver_pair->request = request;
        resolver_pair->src_addr = src_addr;

        if (neat_resolver_create_pair(request->resolver->nc, resolver_pair,
                    &(server_itr->server_addr)) == RETVAL_FAILURE) {
            neat_log(NEAT_LOG_ERROR, "%s - Failed to create resolver pair", __func__);
            neat_resolver_mark_pair_del(request->resolver, resolver_pair);
            continue;
        }

        if (neat_resolver_send_query(resolver_pair, request)) {
            neat_log(NEAT_LOG_ERROR, "%s - Failed to start lookup", __func__);
            neat_resolver_mark_pair_del(request->resolver, resolver_pair);
        } else {
            //printf("Will lookup %s\n", resolver->domain_name);
            LIST_INSERT_HEAD(&(request->resolver_pairs), resolver_pair,
                    next_pair);
        }
    }

    return RETVAL_SUCCESS;
}

//Called when we get a NEAT_DELADDR message. Go though all resolve pairs and
//remove those where src. address match the deleted address
static void neat_resolver_delete_pairs(struct neat_resolver_request *request,
        struct neat_addr *addr_to_delete)
{
    struct sockaddr_in *addr4 = NULL, *addr4_cmp;
    struct sockaddr_in6 *addr6 = NULL, *addr6_cmp;
    struct neat_resolver_src_dst_addr *resolver_pair, *resolver_itr;

    if (addr_to_delete->family == AF_INET)
        addr4 = &(addr_to_delete->u.v4.addr4);
    else
        addr6 = &(addr_to_delete->u.v6.addr6);

    resolver_itr = request->resolver_pairs.lh_first;

    while (resolver_itr != NULL) {
        resolver_pair = resolver_itr;
        resolver_itr = resolver_itr->next_pair.le_next;

        if (resolver_pair->src_addr->family != addr_to_delete->family)
            continue;

        if (addr_to_delete->family == AF_INET && addr4 != NULL) {
            addr4_cmp = &(resolver_pair->src_addr->u.v4.addr4);

            if (addr4_cmp->sin_addr.s_addr == addr4->sin_addr.s_addr)
                neat_resolver_mark_pair_del(request->resolver, resolver_pair);
        } else {
            addr6_cmp = &(resolver_pair->src_addr->u.v6.addr6);

            if (neat_addr_cmp_ip6_addr(&(addr6_cmp->sin6_addr),
                                       &(addr6->sin6_addr))) {
                neat_resolver_mark_pair_del(request->resolver, resolver_pair);
            }
        }
    }
}

//This one will (at least for now) be used to start the first quest. Lets see
//how much we can recycle when we start processing queue
static void neat_start_request(struct neat_resolver *resolver,
                               struct neat_resolver_request *request,
                               int8_t is_literal)
{
    struct neat_addr *nsrc_addr = NULL;

    //node is a literal, so we will just wait a short while for address list to
    //be populated
    if (is_literal) {
        uv_timer_start(&(request->timeout_handle),
                neat_resolver_literal_timeout_cb,
                DNS_LITERAL_TIMEOUT, 0);
        return;
    }

    //Start the resolver timeout, this includes fetching addresses
    uv_timer_start(&(request->timeout_handle), neat_resolver_timeout_cb,
            resolver->dns_t1, 0);

    //No point starting to query if we don't have any source addresses
    if (!resolver->nc->src_addr_cnt) {
        neat_log(NEAT_LOG_ERROR, "%s - No available src addresses", __func__);
        return;
    }

    //Iterate through src addresses, create udp sockets and start requesting
    for (nsrc_addr = resolver->nc->src_addrs.lh_first; nsrc_addr != NULL;
            nsrc_addr = nsrc_addr->next_addr.le_next) {
        if (request->family && nsrc_addr->family != request->family)
            continue;

        //Do not use deprecated addresses
        if (nsrc_addr->family == AF_INET6 && !nsrc_addr->u.v6.ifa_pref)
           continue;

        //TODO: Potential place to filter based on policy

        neat_resolver_create_pairs(nsrc_addr, request);
    }
}

//Public NEAT resolver functions
//getaddrinfo starts a query for the provided service
uint8_t neat_resolve(struct neat_resolver *resolver,
                     uint8_t family,
                     const char *node,
                     uint16_t port,
                     neat_resolver_handle_t handle_resolve,
                     void *user_data)
{
    struct neat_resolver_request *request;
    int8_t is_literal = 0;

    if (port == 0) {
        neat_log(NEAT_LOG_ERROR, "%s - Invalid port specified", __func__);
        return RETVAL_FAILURE;
    }

    if (family && family != AF_INET && family != AF_INET6 && family != AF_UNSPEC) {
        neat_log(NEAT_LOG_ERROR, "%s - Invalid family specified", __func__);
        return RETVAL_FAILURE;
    }

    if ((strlen(node) + 1) > MAX_DOMAIN_LENGTH) {
        neat_log(NEAT_LOG_ERROR, "%s - Domain name too long", __func__);
        return RETVAL_FAILURE;
    }

    request = calloc(sizeof(struct neat_resolver_request), 1);
    request->family = family;
    request->dst_port = htons(port);
    request->resolver = resolver;
    request->user_data = user_data;

    uv_timer_init(resolver->nc->loop, &(request->timeout_handle));
    request->timeout_handle.data = request;

    LIST_INIT(&(request->resolver_pairs));

    //HACK: This is just a hack for testing, will be set based on argument later!
    request->resolve_cb = handle_resolve;

    is_literal = neat_resolver_helpers_check_for_literal(&(request->family),
                                                         node);

    if (is_literal < 0)
        return RETVAL_FAILURE;

    //No need to care about \0, we use calloc ...
    memcpy(request->domain_name, node, strlen(node));

    TAILQ_INSERT_TAIL(&(resolver->request_queue), request, next_req);

    //Start request
    neat_start_request(resolver, request, is_literal);

    return RETVAL_SUCCESS;
}

//Initialize the resolver. Set up callbacks etc.
struct neat_resolver *
neat_resolver_init(struct neat_ctx *nc, const char *resolv_conf_path)
{
    struct neat_resolver *resolver;

    resolver = calloc(sizeof(struct neat_resolver), 1);

    if (!resolver)
        return NULL;

    TAILQ_INIT(&(resolver->request_queue));
    TAILQ_INIT(&(resolver->dead_request_queue));

    //We want to bind a resolver to one context to access address list
    resolver->nc = nc;

    //Same timeouts accross all requests
    //TODO: Might be changed, for example due to different networks. Policy?
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

    LIST_INIT(&(resolver->resolver_pairs_del));

    uv_idle_init(nc->loop, &(resolver->idle_handle));
    resolver->idle_handle.data = resolver;

    if (uv_fs_event_init(nc->loop, &(resolver->resolv_conf_handle))) {
        neat_log(NEAT_LOG_ERROR, "%s - Could not initialize fs event handle", __func__);
        return NULL;
    }

    resolver->resolv_conf_handle.data = resolver;

    if (uv_fs_event_start(&(resolver->resolv_conf_handle),
                      neat_resolver_resolv_conf_updated,
                      resolv_conf_path, 0)) {
        neat_log(NEAT_LOG_WARNING, "%s - Could not start fs event handle", __func__);
    }

    if (!neat_resolver_add_initial_servers(resolver))
        return NULL;

    return resolver;
}

static void neat_resolver_conf_close_cb(uv_handle_t *handle)
{
    struct neat_resolver *resolver = handle->data;
    resolver->fs_event_closed = 1;
}

//Helper function used by both cleanup and reset
static void neat_resolver_cleanup(struct neat_resolver *resolver)
{

    struct neat_resolver_request *request_itr, *request_tmp;
    struct neat_resolver_server *server;
    struct neat_resolver_server *server_next;

    //"Free" all requests
    for (request_itr = resolver->request_queue.tqh_first;
         request_itr != NULL;) {
        request_tmp = request_itr;
        request_itr = request_itr->next_req.tqe_next;
        neat_resolver_request_cleanup(request_tmp);
    }

    neat_remove_event_cb(resolver->nc, NEAT_NEWADDR, &(resolver->newaddr_cb));
    neat_remove_event_cb(resolver->nc, NEAT_DELADDR, &(resolver->deladdr_cb));
    uv_fs_event_stop(&(resolver->resolv_conf_handle));

    if (!uv_is_closing((const uv_handle_t*) &(resolver->resolv_conf_handle)))
        uv_close((uv_handle_t*) &(resolver->resolv_conf_handle),
                neat_resolver_conf_close_cb);

    //Remove all entries in the server table
    LIST_FOREACH_SAFE(server, &(resolver->server_list), next_server, server_next) {
        LIST_REMOVE(server, next_server);
        free(server);
    }
}

void neat_resolver_release(struct neat_resolver *resolver)
{
    struct neat_resolver_request *request_itr, *request_tmp;

    resolver->free_resolver = 1;

    neat_resolver_cleanup(resolver);

    //If loop is not stopped, return. Otherwise, the idle callback will never be
    //called, so we have to manually free the pairs
    if (uv_backend_fd(resolver->nc->loop) != -1) {
        //Idle handle will only be started if we have one or more active pairs.
        //That might not be the case, for example someone has requested IPv6 and
        //only has IPv4 addresses
        //
        //I find it cleaner to use idle here than to look into each request and
        //check for pairs or something. Even though it forces one more iteration
        //of loop ...

        if (!uv_is_active((uv_handle_t*) &(resolver->idle_handle))) {
            uv_idle_start(&(resolver->idle_handle), neat_resolver_idle_cb);
        }

        return;
    }

    neat_resolver_flush_pairs_del(resolver);

    //Free all dead requests
    for (request_itr = resolver->dead_request_queue.tqh_first;
         request_itr != NULL;) {
        request_tmp = request_itr;
        request_itr = request_itr->next_req.tqe_next;

        //No need to remove from list. resolver can't be used after this
        //function is called
        free(request_tmp);
    }

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
