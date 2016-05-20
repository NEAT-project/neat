#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <ldns/ldns.h>
#include <arpa/inet.h>

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

    if ((out = (char *) malloc(sizeof(char) * strlen(reverse_ip))) == NULL) {
        neat_log(NEAT_LOG_ERROR,
                "%s: can't allocate buffer");
        return NULL;
    }
    strcpy(out, reverse_ip);
    return out;
}

void add_pvd_to_addr(struct neat_addr* src_addr, ldns_rr_list *pvd_txt_list) {
    int nb_txt = ldns_rr_list_rr_count(pvd_txt_list);
    struct pvd_infos pvd_infos;
    struct pvd_info* pvd_info;
    char* txt_record;
    ldns_rr *rr;
    ldns_rdf *dns_record = NULL;
    struct pvd* pvd;

    if ((pvd = (struct pvd *) malloc(sizeof(struct pvd))) == NULL) {
        neat_log(NEAT_LOG_ERROR,
                "%s: can't allocate buffer");
        return;
    }
    LIST_INIT(&pvd_infos);

    for (int i = 0; i < nb_txt; i++) {
        rr = ldns_rr_list_rr(pvd_txt_list, i);
        dns_record = ldns_rr_set_rdf(rr, NULL, 0);
        txt_record = strdup(ldns_rdf2str(dns_record));

        // Removing quotes if any
        if (txt_record[0] == '"' && txt_record[strlen(txt_record)-1] == '"') {
            txt_record[strlen(txt_record)-1] = 0;
            txt_record++;
        }

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
        LIST_INSERT_HEAD(&(src_addr->pvds), pvd, next_pvd);
    }

    ldns_rr_list_deep_free(pvd_txt_list);
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
    ldns_rdf *ptr;
    ldns_pkt *p;
    ldns_rr_list *pvd_txt_list;
    ldns_rr_list *pvd_ptr_list;
    ldns_rr *rr;
    ldns_rdf *dns_record = NULL;
    char* ptr_record;
    char* reverse_ip = compute_reverse_ip(src_addr);

    if (strlen(reverse_ip) == 0) {
        return;
    }

    LIST_INIT(&(src_addr->pvds));

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
            rr = ldns_rr_list_rr(pvd_ptr_list, i);
            dns_record = ldns_rr_set_rdf(rr, NULL, 0);
            ptr_record = strdup(ldns_rdf2str(dns_record));
            ptr = ldns_dname_new_frm_str(ptr_record);

            // Performing DNS query to 'dns_addr' for TXT records of 'ptr'
            p = ldns_resolver_query(resolver, ptr, LDNS_RR_TYPE_TXT, LDNS_RR_CLASS_IN, LDNS_RD);
            ldns_rdf_deep_free(ptr);
            if (!p)  {
                continue;
            }
            pvd_txt_list = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_TXT, LDNS_SECTION_ANSWER);
            ldns_pkt_free(p);
            ldns_rr_list_sort(pvd_txt_list);

            // Adding txt records as new pvd record to src_addr
            add_pvd_to_addr(src_addr, pvd_txt_list);
        }

        ldns_rdf_deep_free(dns_src);
        // ldns_rdf_deep_free(dns_record);
        ldns_resolver_deep_free(resolver);
    }
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

    if (neat_add_event_cb(nc, NEAT_NEWADDR, &(pvd->newaddr_cb))) {
        neat_log(NEAT_LOG_ERROR, "%s - Could not add one pvd callbacks", __func__);
        return NULL;
    }

    return pvd;
}
