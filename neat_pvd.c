#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <ldns/ldns.h>
#include <arpa/inet.h>
#ifdef __linux__
    #include <net/if.h>
#endif

#include "neat.h"
#include "neat_internal.h"
#include "neat_resolver.h"
#include "neat_core.h"
#include "neat_pvd.h"
#include "neat_addr.h"

char* compute_reverse_ip(struct neat_addr *src_addr) {
    struct in_addr src_addr4;
    struct in6_addr src_addr6;
    uint8_t family = src_addr->family;
    char reverse_ip[80]; // maximum length for a reverse /128 IPv6
    int i;
    char *out;

    if (family == AF_INET6) {
        // From fd17:625c:f037:2:a00:27ff:fe37:86b6/69 => _.pvd.8.0.7.3.0.f.c.5.2.6.7.1.d.f.ip6.arpa.
        src_addr6 = (src_addr->u.v6.addr6).sin6_addr;
        sprintf(reverse_ip, "_.pvd.");
        int addr_last_part = src_addr->prefix_length & 4;
        int addr_total_hex = src_addr->prefix_length >> 2;
        int string_offset = 6;
        int current_hex;
        i = addr_total_hex-1;

        // if the prefix length is not multiple of 4
        if (addr_last_part != 0) {
            int last_index = addr_total_hex / 2;
            bool divide = (addr_total_hex % 2) == 0;
            if (divide) {
                current_hex = src_addr6.s6_addr[last_index] >> 4;
            } else {
                current_hex = src_addr6.s6_addr[last_index] & 0x0f;
            }
            current_hex = current_hex - (current_hex % (1 << (4 - addr_last_part)));
            sprintf(reverse_ip+string_offset, "%01x.", current_hex);
            string_offset = string_offset + 2;
        }
        while (i >= 0) {
            if (i % 2 == 0) {
                current_hex = src_addr6.s6_addr[i/2] >> 4;
            } else {
                current_hex = src_addr6.s6_addr[i/2] & 0x0f;
            }
            sprintf(reverse_ip + string_offset + 2*(addr_total_hex - 1 - i), "%01x.", current_hex);
            i--;
        }
        sprintf(reverse_ip + string_offset + 2*addr_total_hex, "ip6.arpa.");
    } else if (family == AF_INET) {
        // From 192.168.145.2/19 => _.pvd.128.168.192.in-addr.arpa.
        src_addr4 = (src_addr->u.v4.addr4).sin_addr;
        uint32_t src_addr4_prefix = src_addr4.s_addr & ((1 << src_addr->prefix_length) - 1);

        sprintf(reverse_ip, "_.pvd.");
        for (i = ((src_addr->prefix_length >> 3) << 3) - 8; i >= 0; i -= 8) {
            sprintf(reverse_ip + strlen(reverse_ip), "%u.", ((src_addr4_prefix & (0xff << i)) >> i));
        }

        sprintf(reverse_ip + strlen(reverse_ip), "in-addr.arpa.");
    }

    if ((out = (char *) malloc(sizeof(char) * (strlen(reverse_ip)+1))) == NULL) {
        neat_log(NEAT_LOG_ERROR,
                "%s: can't allocate buffer");
        return NULL;
    }
    strcpy(out, reverse_ip);
    return out;
}

void add_pvd_result(struct pvds* pvds, ldns_rr_list *pvd_txt_list) {
    int nb_txt = ldns_rr_list_rr_count(pvd_txt_list);
    struct pvd_infos pvd_infos;
    struct pvd_info* pvd_info;
    char* txt_record;
    char* dns_record_str;
    ldns_rr *rr;
    ldns_rdf *dns_record = NULL;
    struct pvd* pvd;

    if ((pvd = (struct pvd *) malloc(sizeof(struct pvd))) == NULL) {
        free(pvd);
        neat_log(NEAT_LOG_ERROR,
                "%s: can't allocate buffer");
        return;
    }
    LIST_INIT(&pvd_infos);

    for (int i = 0; i < nb_txt; i++) {
        rr = ldns_rr_list_rr(pvd_txt_list, i);
        dns_record = ldns_rr_set_rdf(rr, NULL, 0);
        dns_record_str = ldns_rdf2str(dns_record);
        txt_record = strdup(dns_record_str);

        // Removing quotes if any
        if (txt_record[0] == '"' && txt_record[strlen(txt_record)-1] == '"') {
            txt_record[strlen(txt_record)-1] = 0;
            txt_record++;
        }

        free(dns_record_str);

        if ((pvd_info = (struct pvd_info *) malloc(sizeof(struct pvd_info))) == NULL) {
            neat_log(NEAT_LOG_ERROR,
                    "%s: can't allocate buffer");
            continue;
        }
        pvd_info->key = strsep(&txt_record, "=");
        pvd_info->value = txt_record;

        LIST_INSERT_HEAD(&(pvd_infos), pvd_info, next_info);
    }

    if (nb_txt > 0) {
        pvd->infos = pvd_infos;
        LIST_INSERT_HEAD(pvds, pvd, next_pvd);
    }
}

static int neat_pvd_dns_async(uv_loop_t* loop, struct sockaddr_storage *dns_addr, struct neat_addr *src_addr, ldns_pkt *pkt, uv_alloc_cb alloc_cb, uv_udp_recv_cb recv_cb, uv_udp_send_cb send_cb, void *data)
{
    struct sockaddr* dns_addr2 = (struct sockaddr*) dns_addr;
    struct sockaddr_in *dst_addr4, *server_addr4;
    struct sockaddr_in6 *dst_addr6, *server_addr6;

    ldns_buffer *dns_snd_buf = calloc(sizeof(ldns_buffer), 1);
    uv_buf_t *dns_uv_snd_buf = calloc(sizeof(uv_buf_t), 1);
    uv_udp_send_t *dns_snd_handle = calloc(sizeof(uv_udp_send_t), 1);
    uv_udp_t *resolve_handle = calloc(sizeof(uv_udp_t), 1);

    ldns_pkt_set_random_id(pkt);
    ldns_pkt_set_rd(pkt, 1);
    ldns_pkt_set_ad(pkt, 1);

    if (uv_udp_init(loop, resolve_handle)) {
        //Closed is normally set in close_cb, but since we will never get that
        //far, set it here instead
        //pair->closed = 1;
        neat_log(NEAT_LOG_ERROR, "%s - Failure to initialize UDP handle", __func__);
        return 1;
    }

    resolve_handle->data = data;

    if (uv_udp_bind(resolve_handle,
                (struct sockaddr*) &(src_addr->u.generic.addr),
                0)) {
        neat_log(NEAT_LOG_ERROR, "%s - Failed to bind UDP socket", __func__);
        return 1;
    }

    if (uv_udp_recv_start(resolve_handle, alloc_cb,
                recv_cb)) {
        neat_log(NEAT_LOG_ERROR, "%s - Failed to start receiving UDP", __func__);
        return 1;
    }

    dns_snd_buf = ldns_buffer_new(LDNS_MIN_BUFLEN);
    if (ldns_pkt2buffer_wire(dns_snd_buf, pkt) != LDNS_STATUS_OK) {
        neat_log(NEAT_LOG_ERROR, "%s - Could not convert pkt to buf", __func__);
        ldns_pkt_free(pkt);
        return 1;
    }

    ldns_pkt_free(pkt);

    dns_uv_snd_buf->base = (char*) ldns_buffer_begin(dns_snd_buf);
    dns_uv_snd_buf->len = ldns_buffer_position(dns_snd_buf);

    if (dns_addr2->sa_family == AF_INET) {
        server_addr4 = (struct sockaddr_in*) dns_addr;
        dst_addr4 = calloc(sizeof(struct sockaddr_in), 1);
        dst_addr4->sin_family = AF_INET;
        dst_addr4->sin_port = htons(LDNS_PORT);
        dst_addr4->sin_addr = server_addr4->sin_addr;
#ifdef HAVE_SIN_LEN
        dst_addr4->sin_len = sizeof(struct sockaddr_in);
#endif

        if (uv_udp_send(dns_snd_handle, resolve_handle,
                dns_uv_snd_buf, 1,
                (const struct sockaddr*) dst_addr4,
                send_cb)) {
            neat_log(NEAT_LOG_ERROR, "%s - Failed to start DNS send", __func__);
            return 1;
        }
    } else {
        server_addr6 = (struct sockaddr_in6*) dns_addr;
        dst_addr6 = calloc(sizeof(struct sockaddr_in6), 1);
        dst_addr6->sin6_family = AF_INET6;
        dst_addr6->sin6_port = htons(LDNS_PORT);
        dst_addr6->sin6_addr = server_addr6->sin6_addr;
#ifdef HAVE_SIN6_LEN
        dst_addr6->sin6_len = sizeof(struct sockaddr_in6);
#endif

        if (uv_udp_send(dns_snd_handle, resolve_handle,
                dns_uv_snd_buf, 1,
                (const struct sockaddr*) dst_addr6,
                send_cb)) {
            neat_log(NEAT_LOG_ERROR, "%s - Failed to start DNS send", __func__);
            return 1;
        }
    }

    return 0;
}

//Called when a DNS request has been (i.e., passed to socket). We will send the
//second query (used for checking poisoning) here. If that is needed
static void neat_pvd_dns_sent_cb(uv_udp_send_t *req, int status)
{
}

//libuv gives the user control of how memory is allocated. This callback is
//called when a UDP packet is ready to received, and we have to fill out the
//provided buf with the storage location (and available size)
static void neat_pvd_dns_alloc_cb(uv_handle_t *handle,
        size_t suggested_size, uv_buf_t *buf)
{
    char *dns_rcv_buf = calloc(sizeof(char), 1472);

    buf->base = dns_rcv_buf;
    buf->len = sizeof(char)*1472;
}

static void neat_pvd_dns_recv_cb(uv_udp_t* handle, ssize_t nread,
        const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    struct pvd_result *pvd_result = handle->data;
    ldns_pkt *dns_reply;
    ldns_rr_list *pvd_txt_list = NULL;
    size_t retval;

    if (nread == 0 && addr == NULL) {
        free(buf->base);
        return;
    }

    retval = ldns_wire2pkt(&dns_reply, (const uint8_t*) buf->base, nread);
    free(buf->base);

    if (retval != LDNS_STATUS_OK)
        return;

    //Parse result
    pvd_txt_list = ldns_pkt_rr_list_by_type(dns_reply, LDNS_RR_TYPE_TXT, LDNS_SECTION_ANSWER);

    if (pvd_txt_list == NULL) {
        ldns_pkt_free(dns_reply);
        return;
    }

    add_pvd_result(&(pvd_result->pvds), pvd_txt_list);

    ldns_rr_list_deep_free(pvd_txt_list);
    ldns_pkt_free(dns_reply);
}

static void neat_pvd_dns_ptr_recv_cb(uv_udp_t* handle, ssize_t nread,
        const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    struct pvd_dns_query *dns_query = handle->data;
    ldns_pkt *dns_reply;
    ldns_rr_list *pvd_ptr_list = NULL;
    size_t retval;
    int i;
    ldns_rr *rr;
    ldns_rdf *dns_record = NULL;
    char* ptr_record;
    char* dns_record_str;

    if (nread == 0 && addr == NULL) {
        free(buf->base);
        return;
    }

    retval = ldns_wire2pkt(&dns_reply, (const uint8_t*) buf->base, nread);
    free(buf->base);

    if (retval != LDNS_STATUS_OK)
        return;

    //Parse result
    pvd_ptr_list = ldns_pkt_rr_list_by_type(dns_reply, LDNS_RR_TYPE_PTR, LDNS_SECTION_ANSWER);

    if (pvd_ptr_list == NULL) {
        ldns_pkt_free(dns_reply);
        return;
    }

    int nb_ptr = ldns_rr_list_rr_count(pvd_ptr_list);

    // There can be multiple PvDs
    for (i = 0; i < nb_ptr; i++) {
        rr = ldns_rr_list_rr(pvd_ptr_list, i);
        dns_record = ldns_rr_set_rdf(rr, NULL, 0);
        dns_record_str = ldns_rdf2str(dns_record);
        ptr_record = strdup(dns_record_str);

        ldns_pkt *pkt;
        if (ldns_pkt_query_new_frm_str(&pkt, ptr_record, LDNS_RR_TYPE_TXT,
                    LDNS_RR_CLASS_IN, LDNS_RD) != LDNS_STATUS_OK) {
            neat_log(NEAT_LOG_ERROR, "%s - Could not create DNS packet", __func__);
            continue;
        }
        free(dns_record_str);
        free(ptr_record);

        neat_pvd_dns_async(dns_query->loop, dns_query->dns_addr, dns_query->src_addr, pkt, neat_pvd_dns_alloc_cb, neat_pvd_dns_recv_cb, neat_pvd_dns_sent_cb, dns_query->pvd_result);
    }

     ldns_rr_list_deep_free(pvd_ptr_list);
     ldns_pkt_free(dns_reply);
}

static void neat_pvd_handle_newaddr(struct neat_ctx *nc,
                                    void *p_ptr,
                                    void *data)
{
    if (LIST_EMPTY(&(nc->resolver->server_list))) {
        // No DNS servers
        return;
    }

    struct neat_addr *src_addr = (struct neat_addr*) data;
    struct neat_resolver_server *dns_server;
    char* reverse_ip = compute_reverse_ip(src_addr);
    struct pvd_result* pvd_result;

    if ((pvd_result = (struct pvd_result *) malloc(sizeof(struct pvd_result))) == NULL) {
        neat_log(NEAT_LOG_ERROR,
                "%s: can't allocate buffer");
        return;
    }

    if (strlen(reverse_ip) == 0) {
        return;
    }

    LIST_INIT(&(pvd_result->pvds));
    pvd_result->src_addr = src_addr;

    LIST_FOREACH(dns_server, &(nc->resolver->server_list), next_server) {
        // Avoid static servers
        if (dns_server->mark != NEAT_RESOLVER_SERVER_ACTIVE) {
            continue;
        }

        struct sockaddr_storage *dns_addr = &(dns_server->server_addr);

        struct pvd_dns_query *dns_query = malloc(sizeof(struct pvd_dns_query));
        dns_query->loop = nc->loop;
        dns_query->src_addr = src_addr;
        dns_query->dns_addr = dns_addr;
        dns_query->pvd_result = pvd_result;

        ldns_pkt *pkt;
        if (ldns_pkt_query_new_frm_str(&pkt, reverse_ip, LDNS_RR_TYPE_PTR,
                    LDNS_RR_CLASS_IN, LDNS_RD) != LDNS_STATUS_OK) {
            neat_log(NEAT_LOG_ERROR, "%s - Could not create DNS packet", __func__);
            continue;
        }

        neat_pvd_dns_async(nc->loop, dns_addr, src_addr, pkt, neat_pvd_dns_alloc_cb, neat_pvd_dns_ptr_recv_cb, neat_pvd_dns_sent_cb, dns_query);

        // ldns_rdf_deep_free(dns_src);
        // ldns_resolver_deep_free(resolver);
        // ldns_rr_list_deep_free(pvd_ptr_list);
    }
    free(reverse_ip);

    LIST_INSERT_HEAD(&(nc->pvd->results), pvd_result, next_result);
}

struct neat_pvd *
neat_pvd_init(struct neat_ctx *nc)
{
    struct neat_pvd *pvd = calloc(sizeof(struct neat_pvd), 1);
    if (!pvd)
        return NULL;

    pvd->nc = nc;

    pvd->newaddr_cb.event_cb = neat_pvd_handle_newaddr;
    pvd->newaddr_cb.data = pvd;
    LIST_INIT(&(pvd->results));

    if (neat_add_event_cb(nc, NEAT_NEWADDR, &(pvd->newaddr_cb))) {
        neat_log(NEAT_LOG_ERROR, "%s - Could not add one pvd callbacks", __func__);
        return NULL;
    }

    return pvd;
}
