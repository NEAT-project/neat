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

//Called when a DNS request has been (i.e., passed to socket). We will send the
//second query (used for checking poisoning) here. If that is needed
static void neat_pvd_dns_sent_cb(uv_udp_send_t *req, int status)
{
    neat_log(NEAT_LOG_INFO, "neat_pvd_dns_sent_cb");
}

//libuv gives the user control of how memory is allocated. This callback is
//called when a UDP packet is ready to received, and we have to fill out the
//provided buf with the storage location (and available size)
static void neat_pvd_dns_alloc_cb(uv_handle_t *handle,
        size_t suggested_size, uv_buf_t *buf)
{
    neat_log(NEAT_LOG_INFO, "neat_pvd_dns_alloc_cb");
    char dns_rcv_buf[1472];

    buf->base = dns_rcv_buf;
    buf->len = sizeof(dns_rcv_buf);
}

static void neat_pvd_dns_recv_cb(uv_udp_t* handle, ssize_t nread,
        const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    neat_log(NEAT_LOG_INFO, "neat_pvd_dns_recv_cb");
    // struct neat_resolver_src_dst_addr *pair = handle->data;
    // ldns_pkt *dns_reply;
    // //Used to store the results of the DNS query
    // ldns_rr_list *rr_list = NULL;
    // ldns_rr *rr_record = NULL;
    // ldns_buffer *host_addr = NULL;
    // ldns_rdf *rdf_result = NULL;
    // ldns_rr_type rr_type;
    // size_t retval, rr_count, i;
    // uint8_t num_resolved = 0, pton_failed = 0;
    // struct sockaddr_in *addr4;
    // struct sockaddr_in6 *addr6;
    //
    // if (nread == 0 && addr == NULL)
    //     return;
    //
    // retval = ldns_wire2pkt(&dns_reply, (const uint8_t*) buf->base, nread);
    //
    // if (retval != LDNS_STATUS_OK)
    //     return;
    //
    // if (pair->src_addr->family == AF_INET)
    //     rr_type = LDNS_RR_TYPE_A;
    // else
    //     rr_type = LDNS_RR_TYPE_AAAA;
    //
    // //Parse result
    // rr_list = ldns_pkt_rr_list_by_type(dns_reply, rr_type, LDNS_SECTION_ANSWER);
    //
    // if (rr_list == NULL) {
    //     ldns_pkt_free(dns_reply);
    //     return;
    // }
    //
    // rr_count = ldns_rr_list_rr_count(rr_list);

    // }
}

static void neat_pvd_handle_newaddr(struct neat_ctx *nc,
                                    void *p_ptr,
                                    void *data)
{
    if (LIST_EMPTY(&(nc->resolver->server_list))) {
        // No DNS servers
        return;
    }

    struct in_addr dns_addr4;
    struct in6_addr dns_addr6;
    struct neat_addr *src_addr = (struct neat_addr*) data;
    struct neat_resolver_server *dns_server;
    int i, nb_ptr;
    ldns_resolver *resolver;
    ldns_rdf *domain;
    ldns_rdf *dns_src;
    // ldns_rdf *ptr;
    ldns_pkt *p;
    // ldns_rr_list *pvd_txt_list;
    ldns_rr_list *pvd_ptr_list;
    // ldns_rr *rr;
    // ldns_rdf *dns_record = NULL;
    // char* ptr_record;
    char* reverse_ip = compute_reverse_ip(src_addr);
    // char* dns_record_str;
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
        if (dns_addr->ss_family == AF_INET6) {
            dns_addr6 = ((struct sockaddr_in6*) dns_addr)->sin6_addr;
            dns_src = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_AAAA, 16, &dns_addr6);
        } else if (dns_addr->ss_family == AF_INET) {
            dns_addr4 = ((struct sockaddr_in*) dns_addr)->sin_addr;
            dns_src = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_A, 4, &dns_addr4);
        } else {
            continue;
        }

        domain = ldns_dname_new_frm_str(reverse_ip);
        resolver = ldns_resolver_new();
        ldns_resolver_push_nameserver(resolver, dns_src);

        // Performing DNS query to 'dns_addr', for PTR records of 'reverse_ip'
        p = ldns_resolver_query(resolver, domain, LDNS_RR_TYPE_PTR, LDNS_RR_CLASS_IN, LDNS_RD);
        ldns_rdf_deep_free(domain);
        if (!p)  {
            continue;
        }
        pvd_ptr_list = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_PTR, LDNS_SECTION_ANSWER);
        ldns_pkt_free(p);
        ldns_rr_list_sort(pvd_ptr_list);
        nb_ptr = ldns_rr_list_rr_count(pvd_ptr_list);

        // There can be multiple PvDs
        for (i = 0; i < nb_ptr; i++) {
            // rr = ldns_rr_list_rr(pvd_ptr_list, i);
            // dns_record = ldns_rr_set_rdf(rr, NULL, 0);
            // dns_record_str = ldns_rdf2str(dns_record);
            // ptr_record = strdup(dns_record_str);
            // ptr = ldns_dname_new_frm_str(ptr_record);

            // We will replace all of this with an asynchrone query

            // // Performing DNS query to 'dns_addr' for TXT records of 'ptr'
            // p = ldns_resolver_query(resolver, ptr, LDNS_RR_TYPE_TXT, LDNS_RR_CLASS_IN, LDNS_RD);
            // ldns_rdf_deep_free(ptr);
            // free(dns_record_str);
            // free(ptr_record);
            // // ldns_rr_list_free(rr);
            // // ldns_rr_free(dns_record);
            // if (!p)  {
            //     continue;
            // }
            // pvd_txt_list = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_TXT, LDNS_SECTION_ANSWER);
            // ldns_pkt_free(p);
            // ldns_rr_list_sort(pvd_txt_list);
            //
            // // Adding txt records as new pvd record to src_addr
            // add_pvd_result(&(pvd_result->pvds), pvd_txt_list);
            // ldns_rr_list_deep_free(pvd_txt_list);

            // neat_log(NEAT_LOG_INFO, "P1");
            // if (ldns_pkt_query_new_frm_str(&p, ptr_record, LDNS_RR_TYPE_TXT,
            //             LDNS_RR_CLASS_IN, 0) != LDNS_STATUS_OK) {
            //     neat_log(NEAT_LOG_ERROR, "%s - Could not create DNS packet", __func__);
            //     continue;
            // }
            //
            // ldns_pkt_set_random_id(p);
            // ldns_pkt_set_rd(p, 1);
            // ldns_pkt_set_ad(p, 1);

            // char dns_rcv_buf[1472];
            // ldns_buffer *dns_snd_buf;
            // uv_buf_t dns_uv_snd_buf;
            // uv_udp_send_t dns_snd_handle;
            uv_udp_t resolve_handle;
            // uv_os_fd_t socket_fd = -1;

            neat_log(NEAT_LOG_INFO, "P2");
            if (uv_udp_init(nc->loop, &resolve_handle)) {
                //Closed is normally set in close_cb, but since we will never get that
                //far, set it here instead
                //pair->closed = 1;
                neat_log(NEAT_LOG_ERROR, "%s - Failure to initialize UDP handle", __func__);
                continue;
            }

            // pair->resolve_handle.data = pair;

            neat_log(NEAT_LOG_INFO, "P2.2");
            if (uv_udp_bind(&resolve_handle,
                        (struct sockaddr*) &(src_addr->u.generic.addr),
                        0)) {
                neat_log(NEAT_LOG_ERROR, "%s - Failed to bind UDP socket", __func__);
                continue;
            }

            neat_log(NEAT_LOG_INFO, "P3");

            // Adding the next 4 lines create a memory problems in neat_resolver
            if (uv_udp_recv_start(&resolve_handle, neat_pvd_dns_alloc_cb,
                        neat_pvd_dns_recv_cb)) {
                neat_log(NEAT_LOG_ERROR, "%s - Failed to start receiving UDP", __func__);
                continue;
            }

            // uv_fileno((uv_handle_t*) &resolve_handle, &socket_fd);

            //
            // neat_log(NEAT_LOG_INFO, "P4");
            // dns_snd_buf = ldns_buffer_new(LDNS_MIN_BUFLEN);
            // if (ldns_pkt2buffer_wire(dns_snd_buf, p) != LDNS_STATUS_OK) {
            //     neat_log(NEAT_LOG_ERROR, "%s - Could not convert pkt to buf", __func__);
            //     ldns_pkt_free(p);
            //     continue;
            // }
            //
            // neat_log(NEAT_LOG_INFO, "P5");
            // ldns_pkt_free(p);
            //
            // dns_uv_snd_buf.base = (char*) ldns_buffer_begin(dns_snd_buf);
            // dns_uv_snd_buf.len = ldns_buffer_position(dns_snd_buf);
            //
            // neat_log(NEAT_LOG_INFO, "P6");
            // if (uv_udp_send(&dns_snd_handle, &resolve_handle,
            //         &dns_uv_snd_buf, 1,
            //         (const struct sockaddr*) dns_addr,
            //         neat_pvd_dns_sent_cb)) {
            //     neat_log(NEAT_LOG_ERROR, "%s - Failed to start DNS send", __func__);
            //     continue;
            // }
            break;
        }

        // ldns_rdf_deep_free(dns_src);
        // ldns_resolver_deep_free(resolver);
        // ldns_rr_list_deep_free(pvd_ptr_list);
    }
    // free(reverse_ip);

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
