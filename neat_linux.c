#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_core.h"
#include "neat_addr.h"
#include "neat_linux.h"
#include "neat_linux_internal.h"
#include "neat_stat.h"

//In order to build a list of available source addresses, we need to start by
//requesting all available addresses. That is the work of this function
static ssize_t neat_linux_request_addrs(struct mnl_socket *mnl_sock)
{
    uint8_t snd_buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nl_hdr = mnl_nlmsg_put_header(snd_buf);

    nl_hdr->nlmsg_type = RTM_GETADDR;
    nl_hdr->nlmsg_pid = getpid();
    nl_hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

    struct rtgenmsg* rt_msg = (struct rtgenmsg*)
        mnl_nlmsg_put_extra_header(nl_hdr, sizeof(struct rtgenmsg));
    rt_msg->rtgen_family = AF_UNSPEC;

    //We should probably have used libuv send function, but right here it does
    //not really matter
    return mnl_socket_sendto(mnl_sock, snd_buf, nl_hdr->nlmsg_len);
}

//Helper function for parsing netfilter attributes
static int neat_linux_parse_nlattr(const struct nlattr *attr, void *data)
{
    struct nlattr_storage *storage = (struct nlattr_storage*) data;
    int32_t type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, storage->limit) < 0)
        return MNL_CB_OK;

    storage->tb[type] = attr;
    return MNL_CB_OK;
}

//Function which parses the netlink message (*ADDR) we have received and extract
//relevant information, which is parsed to OS-independent
//neat_addr_update_src_list
static void neat_linux_handle_addr(struct neat_ctx *nc,
                                   struct nlmsghdr *nl_hdr)
{
    struct ifaddrmsg *ifm = (struct ifaddrmsg*) mnl_nlmsg_get_payload(nl_hdr);
    const struct nlattr *attr_table[IFA_MAX+1];
    //IFA_MAX is the largest index I can store in my array. Since arrays are
    //zero-indexed, this is IFA_MAX and not IFA_MAX + 1. However, array has to
    //be of size IFA_MAX + 1. DOH!
    struct nlattr_storage tb_storage = {attr_table, IFA_MAX};
    struct sockaddr_storage src_addr;
    struct sockaddr_in *src_addr4;
    struct sockaddr_in6 *src_addr6;
    struct ifa_cacheinfo *ci;
    uint32_t ifa_pref = 0, ifa_valid = 0;

    if (ifm->ifa_scope == RT_SCOPE_LINK)
        return;

    memset(attr_table, 0, sizeof(attr_table));
    memset(&src_addr, 0, sizeof(src_addr));

    if (mnl_attr_parse(nl_hdr, sizeof(struct ifaddrmsg),
                neat_linux_parse_nlattr, &tb_storage) != MNL_CB_OK) {
        neat_log(NEAT_LOG_ERROR, "Failed to parse nlattr for msg of type %d",
                __func__, nl_hdr->nlmsg_type);
        return;
    }

    //v4 and v6 has to be handled differently, both due to address size and
    //available information
    if (ifm->ifa_family == AF_INET) {
        src_addr4 = (struct sockaddr_in*) &src_addr;
        src_addr4->sin_family = AF_INET;
        src_addr4->sin_addr.s_addr = mnl_attr_get_u32(attr_table[IFA_LOCAL]);
    } else {
        src_addr6 = (struct sockaddr_in6*) &src_addr;
        src_addr6->sin6_family = AF_INET6;
        memcpy(&src_addr6->sin6_addr, mnl_attr_get_payload(attr_table[IFA_ADDRESS]), sizeof(struct in6_addr));

        ci = (struct ifa_cacheinfo*) mnl_attr_get_payload(attr_table[IFA_CACHEINFO]);
        ifa_pref = ci->ifa_prefered;
        ifa_valid = ci->ifa_valid;
    }

    //TODO: Should this function be a callback instead? Will we have multiple
    //addresses handlers/types of context?
    neat_addr_update_src_list(nc, &src_addr, ifm->ifa_index,
            nl_hdr->nlmsg_type == RTM_NEWADDR, ifm->ifa_prefixlen, ifa_pref, ifa_valid);
}

//libuv datagram socket alloc function, un-interesting
static void neat_linux_nl_alloc(uv_handle_t *handle, size_t suggested_size,
        uv_buf_t *buf)
{
    struct neat_ctx *nc = handle->data;

    memset(nc->mnl_rcv_buf, 0, MNL_SOCKET_BUFFER_SIZE);
    buf->base = nc->mnl_rcv_buf;
    buf->len = MNL_SOCKET_BUFFER_SIZE;
}

//libuv dgram socket callback. Only checks if message is of right type and then
//call function for parsing message
static void neat_linux_nl_recv(uv_udp_t *handle, ssize_t nread,
        const uv_buf_t *buf, const struct sockaddr *addr, unsigned int flags)
{
    struct neat_ctx *nc = (struct neat_ctx*) handle->data;
    struct nlmsghdr *nl_hdr = (struct nlmsghdr*) buf->base;
    //We don't need any check here, we don't read more than 8192 bytes in one go
    int numbytes = (int) nread;

    while (mnl_nlmsg_ok(nl_hdr, numbytes)) {
        if (nl_hdr->nlmsg_type == RTM_NEWADDR ||
            nl_hdr->nlmsg_type == RTM_DELADDR)
            neat_linux_handle_addr(nc, nl_hdr);

        nl_hdr = mnl_nlmsg_next(nl_hdr, &numbytes);
    }
}

//Out cleanup callback, nothing interesting here
static void neat_linux_cleanup(struct neat_ctx *nc)
{
    if (nc->mnl_sock)
        mnl_socket_close(nc->mnl_sock);

    free(nc->mnl_rcv_buf);
}

//Initialize the Linux-specific part of the context. All is related to
//libmnl/netfilter
struct neat_ctx *neat_linux_init_ctx(struct neat_ctx *nc)
{
    //TODO: Consider allocator function
    if ((nc->mnl_rcv_buf = calloc(MNL_SOCKET_BUFFER_SIZE, 1)) == NULL) {
        neat_log(NEAT_LOG_ERROR, "Failed to allocate netlink buffer", __func__);
        return NULL;
    }

    //Configure netlink and start requesting addresses
    if ((nc->mnl_sock = mnl_socket_open(NETLINK_ROUTE)) == NULL) {
        neat_log(NEAT_LOG_ERROR, "Failed to allocate netlink socket", __func__);
        return NULL;
    }

    if (mnl_socket_bind(nc->mnl_sock, (1 << (RTNLGRP_IPV4_IFADDR - 1)) |
                (1 << (RTNLGRP_IPV6_IFADDR - 1)), 0)) {
        neat_log(NEAT_LOG_ERROR, "Failed to bind netlink socket", __func__);
        return NULL;
    }

    //We need to build a list of all available source addresses as soon as
    //possible. It is started here
    if (neat_linux_request_addrs(nc->mnl_sock) <= 0) {
        neat_log(NEAT_LOG_ERROR, "Failed to request addresses", __func__);
        return NULL;
    }

    //Add socket to event loop
    if (uv_udp_init(nc->loop, &(nc->uv_nl_handle))) {
        neat_log(NEAT_LOG_ERROR, "Failed to initialize uv UDP handle", __func__);
        return NULL;
    }

    //TODO: We could use offsetof, but libuv has a pointer so ...
    nc->uv_nl_handle.data = nc;

    if (uv_udp_open(&(nc->uv_nl_handle), mnl_socket_get_fd(nc->mnl_sock))) {
        neat_log(NEAT_LOG_ERROR, "Could not add netlink socket to uv", __func__);
        return NULL;
    }

    if (uv_udp_recv_start(&(nc->uv_nl_handle), neat_linux_nl_alloc,
                neat_linux_nl_recv)) {
        neat_log(NEAT_LOG_ERROR, "Could not start receiving netlink packets", __func__);
        return NULL;
    }

    nc->cleanup = neat_linux_cleanup;

    //Configure netlink socket, add to event loop and start dumping
    return nc;
}

/* Get the Linux TCP_INFO and copy the relevant fields into the neat-specific 
 * TCP_INFO struct. Return pointer to the struct with the copied data */
void linux_get_tcp_info(neat_flow *flow, struct neat_tcp_info *neat_tcp_info)
{
    int tcp_info_length; 
    struct tcp_info tcpi;
   
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
    
    tcp_info_length = sizeof(struct tcp_info);
    getsockopt(flow->socket->fd, SOL_TCP, TCP_INFO, (void *)&tcpi, (socklen_t *)&tcp_info_length );
    
    /* Copy relevant fields between structs */

    neat_tcp_info->retransmits = tcpi.tcpi_retransmits; 
    neat_tcp_info->tcpi_pmtu = tcpi.tcpi_pmtu; 
    neat_tcp_info->tcpi_rcv_ssthresh = tcpi.tcpi_rcv_ssthresh;
    neat_tcp_info->tcpi_rtt = tcpi.tcpi_rtt;
    neat_tcp_info->tcpi_rttvar = tcpi.tcpi_rttvar;
    neat_tcp_info->tcpi_snd_ssthresh = tcpi.tcpi_snd_ssthresh;
    neat_tcp_info->tcpi_snd_cwnd = tcpi.tcpi_snd_cwnd;
    neat_tcp_info->tcpi_advmss = tcpi.tcpi_advmss;
    neat_tcp_info->tcpi_reordering = tcpi.tcpi_reordering;    
    neat_tcp_info->tcpi_rcv_rtt = tcpi.tcpi_rcv_rtt;
    neat_tcp_info->tcpi_rcv_space = tcpi.tcpi_rcv_space;
    neat_tcp_info->tcpi_total_retrans = tcpi.tcpi_total_retrans;
}
