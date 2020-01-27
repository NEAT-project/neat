#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "opts.h"
#include "pm_utils.h"

unsigned long hash_djb2(unsigned char *str) 
{
    unsigned long hash = 5381;
    int c;

    while (c = *str++) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}

int get_socket_level(char *str) {
    unsigned long h = hash_djb2(str);

    switch (h)
    {
    case H_SOL_SOCKET:
        return SOL_SOCKET;

    case H_SOL_RAW:
        return SOL_RAW;

    case H_SOL_DECNET:
        return SOL_DECNET;

    case H_SOL_X25:
        return SOL_X25;

    case H_SOL_PACKET:
        return SOL_PACKET;

    case H_SOL_ATM:
        return SOL_ATM;

    case H_SOL_AAL:
        return SOL_AAL;

    case H_SOL_IRDA:
        return SOL_IRDA;

    case H_SOL_NETBEUI:
        return SOL_NETBEUI;

    case H_SOL_LLC:
        return SOL_LLC;

    case H_SOL_DCCP:
        return SOL_DCCP;

    case H_SOL_NETLINK:
        return SOL_NETLINK;

    case H_SOL_TIPC:
        return SOL_TIPC;

    case H_SOL_RXRPC:
        return SOL_RXRPC;

    case H_SOL_PPPOL2TP:
        return SOL_PPPOL2TP;

    case H_SOL_BLUETOOTH:
        return SOL_BLUETOOTH;

    case H_SOL_PNPIPE:
        return SOL_PNPIPE;

    case H_SOL_RDS:
        return SOL_RDS;

    case H_SOL_IUCV:
        return SOL_IUCV;

    case H_SOL_CAIF:
        return SOL_CAIF;

    case H_SOL_ALG:
        return SOL_ALG;

    case H_SOL_NFC:
        return SOL_NFC;

    case H_SOL_KCM:
        return SOL_KCM;

    case H_SOL_TLS:
        return SOL_TLS;

    case H_SOL_IP:
	    return SOL_IP;

    case H_SOL_IPV6:
	    return SOL_IPV6;

    case H_SOL_ICMPV6:
	    return SOL_ICMPV6;

    case H_SOL_SCTP:
	    return SOL_SCTP;

    case H_SOL_TCP:
        return SOL_TCP;

    case H_SOL_UDP:
        return SOL_UDP;

    case H_IPPROTO_IP:
	    return IPPROTO_IP;

    case H_IPPROTO_ICMP:
        return IPPROTO_ICMP;

    case H_IPPROTO_IGMP:
        return IPPROTO_IGMP;

    case H_IPPROTO_IPIP:
        return IPPROTO_IPIP;

    case H_IPPROTO_TCP:
        return IPPROTO_TCP;

    case H_IPPROTO_EGP:
        return IPPROTO_EGP;

    case H_IPPROTO_PUP:
        return IPPROTO_PUP;

    case H_IPPROTO_UDP:
        return IPPROTO_UDP;

    case H_IPPROTO_IDP:
        return IPPROTO_IDP;

    case H_IPPROTO_TP:
        return IPPROTO_TP;

    case H_IPPROTO_DCCP:
        return IPPROTO_DCCP;

    case H_IPPROTO_IPV6:
        return IPPROTO_IPV6;

    case H_IPPROTO_RSVP:
        return IPPROTO_RSVP;

    case H_IPPROTO_GRE:
        return IPPROTO_GRE;

    case H_IPPROTO_ESP:
        return IPPROTO_ESP;

    case H_IPPROTO_AH:
        return IPPROTO_AH;

    case H_IPPROTO_MTP:
        return IPPROTO_MTP;

    case H_IPPROTO_BEETPH:
        return IPPROTO_BEETPH;

    case H_IPPROTO_ENCAP:
        return IPPROTO_ENCAP;

    case H_IPPROTO_PIM:
        return IPPROTO_PIM;

    case H_IPPROTO_COMP:
        return IPPROTO_COMP;

    case H_IPPROTO_SCTP:
        return IPPROTO_SCTP;

    case H_IPPROTO_UDPLITE:
        return IPPROTO_UDPLITE;

    case H_IPPROTO_MPLS:
        return IPPROTO_MPLS;

    case H_IPPROTO_RAW:
        return IPPROTO_RAW;

    case H_IPPROTO_HOPOPTS:
        return IPPROTO_HOPOPTS;

    case H_IPPROTO_ROUTING:
        return IPPROTO_ROUTING;

    case H_IPPROTO_FRAGMENT:
        return IPPROTO_FRAGMENT;

    case H_IPPROTO_ICMPV6:
        return IPPROTO_ICMPV6;

    case H_IPPROTO_NONE:
        return IPPROTO_NONE;

    case H_IPPROTO_DSTOPTS:
        return IPPROTO_DSTOPTS;

    case H_IPPROTO_MH:
	    return IPPROTO_MH;

    default:
        return -1;
    }
}

int get_optname(char *str) {
    unsigned long h = hash_djb2(str);

    switch (h)
    {
    case H_SO_DEBUG:
	    return SO_DEBUG;

    case H_SO_REUSEADDR:
        return SO_REUSEADDR;

    case H_SO_TYPE:
        return SO_TYPE;

    case H_SO_ERROR:
        return SO_ERROR;

    case H_SO_DONTROUTE:
        return SO_DONTROUTE;

    case H_SO_BROADCAST:
        return SO_BROADCAST;

    case H_SO_SNDBUF:
        return SO_SNDBUF;

    case H_SO_RCVBUF:
        return SO_RCVBUF;

    case H_SO_SNDBUFFORCE:
        return SO_SNDBUFFORCE;

    case H_SO_RCVBUFFORCE:
        return SO_RCVBUFFORCE;

    case H_SO_KEEPALIVE:
        return SO_KEEPALIVE;

    case H_SO_OOBINLINE:
        return SO_OOBINLINE;

    case H_SO_NO_CHECK:
        return SO_NO_CHECK;

    case H_SO_PRIORITY:
        return SO_PRIORITY;

    case H_SO_LINGER:
        return SO_LINGER;

    case H_SO_BSDCOMPAT:
        return SO_BSDCOMPAT;

    case H_SO_REUSEPORT:
        return SO_REUSEPORT;

    case H_SO_PASSCRED:
        return SO_PASSCRED;

    case H_SO_PEERCRED:
        return SO_PEERCRED;

    case H_SO_RCVLOWAT:
        return SO_RCVLOWAT;

    case H_SO_SNDLOWAT:
        return SO_SNDLOWAT;

    case H_SO_RCVTIMEO:
        return SO_RCVTIMEO;

    case H_SO_SNDTIMEO:
        return SO_SNDTIMEO;

    case H_SO_SECURITY_AUTHENTICATION:
        return SO_SECURITY_AUTHENTICATION;

    case H_SO_SECURITY_ENCRYPTION_TRANSPORT:
        return SO_SECURITY_ENCRYPTION_TRANSPORT;

    case H_SO_SECURITY_ENCRYPTION_NETWORK:
        return SO_SECURITY_ENCRYPTION_NETWORK;

    case H_SO_BINDTODEVICE:
        return SO_BINDTODEVICE;

    case H_SO_ATTACH_FILTER:
        return SO_ATTACH_FILTER;

    case H_SO_DETACH_FILTER:
        return SO_DETACH_FILTER;

    case H_SO_GET_FILTER:
        return SO_GET_FILTER;

    case H_SO_PEERNAME:
        return SO_PEERNAME;

    case H_SO_TIMESTAMP:
        return SO_TIMESTAMP;

    case H_SCM_TIMESTAMP:
        return SCM_TIMESTAMP;

    case H_SO_ACCEPTCONN:
        return SO_ACCEPTCONN;

    case H_SO_PEERSEC:
        return SO_PEERSEC;

    case H_SO_PASSSEC:
        return SO_PASSSEC;

    case H_SO_TIMESTAMPNS:
        return SO_TIMESTAMPNS;

    case H_SCM_TIMESTAMPNS:
        return SCM_TIMESTAMPNS;

    case H_SO_MARK:
        return SO_MARK;

    case H_SO_TIMESTAMPING:
        return SO_TIMESTAMPING;

    case H_SCM_TIMESTAMPING:
        return SCM_TIMESTAMPING;

    case H_SO_PROTOCOL:
        return SO_PROTOCOL;

    case H_SO_DOMAIN:
        return SO_DOMAIN;

    case H_SO_RXQ_OVFL:
        return SO_RXQ_OVFL;

    case H_SO_WIFI_STATUS:
        return SO_WIFI_STATUS;

    case H_SCM_WIFI_STATUS:
        return SCM_WIFI_STATUS;

    case H_SO_PEEK_OFF:
        return SO_PEEK_OFF;

    case H_SO_NOFCS:
        return SO_NOFCS;

    case H_SO_LOCK_FILTER:
        return SO_LOCK_FILTER;

    case H_SO_SELECT_ERR_QUEUE:
        return SO_SELECT_ERR_QUEUE;

    case H_SO_BUSY_POLL:
        return SO_BUSY_POLL;

    case H_SO_MAX_PACING_RATE:
        return SO_MAX_PACING_RATE;

    case H_SO_BPF_EXTENSIONS:
        return SO_BPF_EXTENSIONS;

    case H_SO_INCOMING_CPU:
        return SO_INCOMING_CPU;

    case H_SO_ATTACH_BPF:
        return SO_ATTACH_BPF;

    case H_SO_DETACH_BPF:
        return SO_DETACH_BPF;

    case H_SO_ATTACH_REUSEPORT_CBPF:
        return SO_ATTACH_REUSEPORT_CBPF;

    case H_SO_ATTACH_REUSEPORT_EBPF:
        return SO_ATTACH_REUSEPORT_EBPF;

    case H_SO_CNX_ADVICE:
        return SO_CNX_ADVICE;

    case H_SO_MEMINFO:
        return SO_MEMINFO;

    case H_SO_INCOMING_NAPI_ID:
        return SO_INCOMING_NAPI_ID;

    case H_SO_COOKIE:
        return SO_COOKIE;

    case H_SO_PEERGROUPS:
        return SO_PEERGROUPS;

    case H_SO_ZEROCOPY:
        return SO_ZEROCOPY;

    case H_IP_OPTIONS:
        return IP_OPTIONS;

    case H_IP_HDRINCL:
        return IP_HDRINCL;

    case H_IP_TOS:
        return IP_TOS;

    case H_IP_TTL:
        return IP_TTL;

    case H_IP_RECVOPTS:
        return IP_RECVOPTS;

    case H_IP_RECVRETOPTS:
        return IP_RECVRETOPTS;

    case H_IP_RETOPTS:
        return IP_RETOPTS;

    case H_IP_MULTICAST_IF:
        return IP_MULTICAST_IF;

    case H_IP_MULTICAST_TTL:
        return IP_MULTICAST_TTL;

    case H_IP_MULTICAST_LOOP:
        return IP_MULTICAST_LOOP;

    case H_IP_ADD_MEMBERSHIP:
        return IP_ADD_MEMBERSHIP;

    case H_IP_DROP_MEMBERSHIP:
        return IP_DROP_MEMBERSHIP;

    case H_IP_UNBLOCK_SOURCE:
        return IP_UNBLOCK_SOURCE;

    case H_IP_BLOCK_SOURCE:
        return IP_BLOCK_SOURCE;

    case H_IP_ADD_SOURCE_MEMBERSHIP:
        return IP_ADD_SOURCE_MEMBERSHIP;

    case H_IP_DROP_SOURCE_MEMBERSHIP:
        return IP_DROP_SOURCE_MEMBERSHIP;

    case H_IP_MSFILTER:
        return IP_MSFILTER;

    case H_MCAST_JOIN_GROUP:
        return MCAST_JOIN_GROUP;

    case H_MCAST_BLOCK_SOURCE:
        return MCAST_BLOCK_SOURCE;

    case H_MCAST_UNBLOCK_SOURCE:
        return MCAST_UNBLOCK_SOURCE;

    case H_MCAST_LEAVE_GROUP:
        return MCAST_LEAVE_GROUP;

    case H_MCAST_JOIN_SOURCE_GROUP:
        return MCAST_JOIN_SOURCE_GROUP;

    case H_MCAST_LEAVE_SOURCE_GROUP:
        return MCAST_LEAVE_SOURCE_GROUP;

    case H_MCAST_MSFILTER:
        return MCAST_MSFILTER;

    case H_IP_MULTICAST_ALL:
        return IP_MULTICAST_ALL;

    case H_IP_UNICAST_IF:
        return IP_UNICAST_IF;

    case H_MCAST_EXCLUDE:
        return MCAST_EXCLUDE;

    case H_MCAST_INCLUDE:
        return MCAST_INCLUDE;

    case H_IP_ROUTER_ALERT:
        return IP_ROUTER_ALERT;

    case H_IP_PKTINFO:
        return IP_PKTINFO;

    case H_IP_PKTOPTIONS:
        return IP_PKTOPTIONS;

    case H_IP_PMTUDISC:
        return IP_PMTUDISC;

    case H_IP_MTU_DISCOVER:
        return IP_MTU_DISCOVER;

    case H_IP_RECVERR:
        return IP_RECVERR;

    case H_IP_RECVTTL:
        return IP_RECVTTL;

    case H_IP_RECVTOS:
        return IP_RECVTOS;

    case H_IP_MTU:
        return IP_MTU;

    case H_IP_FREEBIND:
        return IP_FREEBIND;

    case H_IP_IPSEC_POLICY:
        return IP_IPSEC_POLICY;

    case H_IP_XFRM_POLICY:
        return IP_XFRM_POLICY;

    case H_IP_PASSSEC:
        return IP_PASSSEC;

    case H_IP_TRANSPARENT:
        return IP_TRANSPARENT;

    case H_IP_ORIGDSTADDR:
        return IP_ORIGDSTADDR;

    case H_IP_RECVORIGDSTADDR:
        return IP_RECVORIGDSTADDR;

    case H_IP_MINTTL:
        return IP_MINTTL;

    case H_IP_NODEFRAG:
        return IP_NODEFRAG;

    case H_IP_CHECKSUM:
        return IP_CHECKSUM;

    case H_IP_BIND_ADDRESS_NO_PORT:
        return IP_BIND_ADDRESS_NO_PORT;

    case H_IP_RECVFRAGSIZE:
        return IP_RECVFRAGSIZE;

    case H_IP_PMTUDISC_DONT:
        return IP_PMTUDISC_DONT;

    case H_IP_PMTUDISC_WANT:
        return IP_PMTUDISC_WANT;

    case H_IP_PMTUDISC_DO:
        return IP_PMTUDISC_DO;

    case H_IP_PMTUDISC_PROBE:
        return IP_PMTUDISC_PROBE;

    case H_IP_PMTUDISC_INTERFACE:
        return IP_PMTUDISC_INTERFACE;

    case H_IP_PMTUDISC_OMIT:
        return IP_PMTUDISC_OMIT;

    case H_IP_DEFAULT_MULTICAST_TTL:
        return IP_DEFAULT_MULTICAST_TTL;

    case H_IP_DEFAULT_MULTICAST_LOOP:
        return IP_DEFAULT_MULTICAST_LOOP;

    case H_IP_MAX_MEMBERSHIPS:
        return IP_MAX_MEMBERSHIPS;

    case H_IPV6_ADDRFORM:
        return IPV6_ADDRFORM;

    case H_IPV6_2292PKTINFO:
        return IPV6_2292PKTINFO;

    case H_IPV6_2292HOPOPTS:
        return IPV6_2292HOPOPTS;

    case H_IPV6_2292DSTOPTS:
        return IPV6_2292DSTOPTS;

    case H_IPV6_2292RTHDR:
        return IPV6_2292RTHDR;

    case H_IPV6_2292PKTOPTIONS:
        return IPV6_2292PKTOPTIONS;

    case H_IPV6_CHECKSUM:
        return IPV6_CHECKSUM;

    case H_IPV6_2292HOPLIMIT:
        return IPV6_2292HOPLIMIT;

    case H_IPV6_NEXTHOP:
        return IPV6_NEXTHOP;

    case H_IPV6_AUTHHDR:
        return IPV6_AUTHHDR;

    case H_IPV6_UNICAST_HOPS:
        return IPV6_UNICAST_HOPS;

    case H_IPV6_MULTICAST_IF:
        return IPV6_MULTICAST_IF;

    case H_IPV6_MULTICAST_HOPS:
        return IPV6_MULTICAST_HOPS;

    case H_IPV6_MULTICAST_LOOP:
        return IPV6_MULTICAST_LOOP;

    case H_IPV6_JOIN_GROUP:
        return IPV6_JOIN_GROUP;

    case H_IPV6_LEAVE_GROUP:
        return IPV6_LEAVE_GROUP;

    case H_IPV6_ROUTER_ALERT:
        return IPV6_ROUTER_ALERT;

    case H_IPV6_MTU_DISCOVER:
        return IPV6_MTU_DISCOVER;

    case H_IPV6_MTU:
        return IPV6_MTU;

    case H_IPV6_RECVERR:
        return IPV6_RECVERR;

    case H_IPV6_V6ONLY:
        return IPV6_V6ONLY;

    case H_IPV6_JOIN_ANYCAST:
        return IPV6_JOIN_ANYCAST;

    case H_IPV6_LEAVE_ANYCAST:
        return IPV6_LEAVE_ANYCAST;

    case H_IPV6_IPSEC_POLICY:
        return IPV6_IPSEC_POLICY;

    case H_IPV6_XFRM_POLICY:
        return IPV6_XFRM_POLICY;

    case H_IPV6_HDRINCL:
        return IPV6_HDRINCL;

    case H_IPV6_RECVPKTINFO:
        return IPV6_RECVPKTINFO;

    case H_IPV6_PKTINFO:
        return IPV6_PKTINFO;

    case H_IPV6_RECVHOPLIMIT:
        return IPV6_RECVHOPLIMIT;

    case H_IPV6_HOPLIMIT:
        return IPV6_HOPLIMIT;

    case H_IPV6_RECVHOPOPTS:
        return IPV6_RECVHOPOPTS;

    case H_IPV6_HOPOPTS:
        return IPV6_HOPOPTS;

    case H_IPV6_RTHDRDSTOPTS:
        return IPV6_RTHDRDSTOPTS;

    case H_IPV6_RECVRTHDR:
        return IPV6_RECVRTHDR;

    case H_IPV6_RTHDR:
        return IPV6_RTHDR;

    case H_IPV6_RECVDSTOPTS:
        return IPV6_RECVDSTOPTS;

    case H_IPV6_DSTOPTS:
        return IPV6_DSTOPTS;

    case H_IPV6_RECVPATHMTU:
        return IPV6_RECVPATHMTU;

    case H_IPV6_PATHMTU:
        return IPV6_PATHMTU;

    case H_IPV6_DONTFRAG:
        return IPV6_DONTFRAG;

    case H_IPV6_RECVTCLASS:
        return IPV6_RECVTCLASS;

    case H_IPV6_TCLASS:
        return IPV6_TCLASS;

    case H_IPV6_AUTOFLOWLABEL:
        return IPV6_AUTOFLOWLABEL;

    case H_IPV6_ADDR_PREFERENCES:
        return IPV6_ADDR_PREFERENCES;

    case H_IPV6_MINHOPCOUNT:
        return IPV6_MINHOPCOUNT;

    case H_IPV6_ORIGDSTADDR:
        return IPV6_ORIGDSTADDR;

    case H_IPV6_RECVORIGDSTADDR:
        return IPV6_RECVORIGDSTADDR;

    case H_IPV6_TRANSPARENT:
        return IPV6_TRANSPARENT;

    case H_IPV6_UNICAST_IF:
        return IPV6_UNICAST_IF;

    case H_IPV6_RECVFRAGSIZE:
        return IPV6_RECVFRAGSIZE;

    case H_IPV6_ADD_MEMBERSHIP:
        return IPV6_ADD_MEMBERSHIP;

    case H_IPV6_DROP_MEMBERSHIP:
        return IPV6_DROP_MEMBERSHIP;

    case H_IPV6_RXHOPOPTS:
        return IPV6_RXHOPOPTS;

    case H_IPV6_RXDSTOPTS:
        return IPV6_RXDSTOPTS;

    case H_IPV6_PMTUDISC_DONT:
        return IPV6_PMTUDISC_DONT;

    case H_IPV6_PMTUDISC_WANT:
        return IPV6_PMTUDISC_WANT;

    case H_IPV6_PMTUDISC_DO:
        return IPV6_PMTUDISC_DO;

    case H_IPV6_PMTUDISC_PROBE:
        return IPV6_PMTUDISC_PROBE;

    case H_IPV6_PMTUDISC_INTERFACE:
        return IPV6_PMTUDISC_INTERFACE;

    case H_IPV6_PMTUDISC_OMIT:
        return IPV6_PMTUDISC_OMIT;

    case H_IPV6_RTHDR_LOOSE:
        return IPV6_RTHDR_LOOSE;

    case H_IPV6_RTHDR_STRICT:
        return IPV6_RTHDR_STRICT;

    case H_IPV6_RTHDR_TYPE_0:
        return IPV6_RTHDR_TYPE_0;

    case H_SCTP_RTOINFO:
        return SCTP_RTOINFO;

    case H_SCTP_ASSOCINFO:
        return SCTP_ASSOCINFO;

    case H_SCTP_INITMSG:
        return SCTP_INITMSG;

    case H_SCTP_NODELAY:
        return SCTP_NODELAY;

    case H_SCTP_AUTOCLOSE:
        return SCTP_AUTOCLOSE;

    case H_SCTP_SET_PEER_PRIMARY_ADDR:
        return SCTP_SET_PEER_PRIMARY_ADDR;

    case H_SCTP_PRIMARY_ADDR:
        return SCTP_PRIMARY_ADDR;

    case H_SCTP_ADAPTATION_LAYER:
        return SCTP_ADAPTATION_LAYER;

    case H_SCTP_DISABLE_FRAGMENTS:
        return SCTP_DISABLE_FRAGMENTS;

    case H_SCTP_PEER_ADDR_PARAMS:
        return SCTP_PEER_ADDR_PARAMS;

    case H_SCTP_DEFAULT_SEND_PARAM:
        return SCTP_DEFAULT_SEND_PARAM;

    case H_SCTP_EVENTS:
        return SCTP_EVENTS;

    case H_SCTP_I_WANT_MAPPED_V4_ADDR:
        return SCTP_I_WANT_MAPPED_V4_ADDR;

    case H_SCTP_MAXSEG:
        return SCTP_MAXSEG;

    case H_SCTP_STATUS:
        return SCTP_STATUS;

    case H_SCTP_GET_PEER_ADDR_INFO:
        return SCTP_GET_PEER_ADDR_INFO;

    case H_SCTP_DELAYED_ACK_TIME:
        return SCTP_DELAYED_ACK_TIME;

    case H_SCTP_DELAYED_ACK:
        return SCTP_DELAYED_ACK;

    case H_SCTP_DELAYED_SACK:
        return SCTP_DELAYED_SACK;

    case H_SCTP_CONTEXT:
        return SCTP_CONTEXT;

    case H_SCTP_FRAGMENT_INTERLEAVE:
        return SCTP_FRAGMENT_INTERLEAVE;

    case H_SCTP_PARTIAL_DELIVERY_POINT:
        return SCTP_PARTIAL_DELIVERY_POINT;

    case H_SCTP_MAX_BURST:
        return SCTP_MAX_BURST;

    case H_SCTP_AUTH_CHUNK:
        return SCTP_AUTH_CHUNK;

    case H_SCTP_HMAC_IDENT:
        return SCTP_HMAC_IDENT;

    case H_SCTP_AUTH_KEY:
        return SCTP_AUTH_KEY;

    case H_SCTP_AUTH_ACTIVE_KEY:
        return SCTP_AUTH_ACTIVE_KEY;

    case H_SCTP_AUTH_DELETE_KEY:
        return SCTP_AUTH_DELETE_KEY;

    case H_SCTP_PEER_AUTH_CHUNKS:
        return SCTP_PEER_AUTH_CHUNKS;

    case H_SCTP_LOCAL_AUTH_CHUNKS:
        return SCTP_LOCAL_AUTH_CHUNKS;

    case H_SCTP_GET_ASSOC_NUMBER:
        return SCTP_GET_ASSOC_NUMBER;

    case H_SCTP_SOCKOPT_BINDX_ADD:
        return SCTP_SOCKOPT_BINDX_ADD;

    case H_SCTP_SOCKOPT_BINDX_REM:
        return SCTP_SOCKOPT_BINDX_REM;

    case H_SCTP_SOCKOPT_PEELOFF:
        return SCTP_SOCKOPT_PEELOFF;

    case H_SCTP_SOCKOPT_CONNECTX_OLD:
        return SCTP_SOCKOPT_CONNECTX_OLD;

    case H_SCTP_GET_PEER_ADDRS:
        return SCTP_GET_PEER_ADDRS;

    case H_SCTP_GET_LOCAL_ADDRS:
        return SCTP_GET_LOCAL_ADDRS;

    case H_SCTP_SOCKOPT_CONNECTX:
        return SCTP_SOCKOPT_CONNECTX;

    case H_SCTP_SOCKOPT_CONNECTX3:
        return SCTP_SOCKOPT_CONNECTX3;

    case H_SCTP_GET_ASSOC_STATS:
        return SCTP_GET_ASSOC_STATS;

    case H_TCP_NODELAY:
        return TCP_NODELAY;

    case H_TCP_MAXSEG:
        return TCP_MAXSEG;

    case H_TCP_CORK:
        return TCP_CORK;

    case H_TCP_KEEPIDLE:
        return TCP_KEEPIDLE;

    case H_TCP_KEEPINTVL:
        return TCP_KEEPINTVL;

    case H_TCP_KEEPCNT:
        return TCP_KEEPCNT;

    case H_TCP_SYNCNT:
        return TCP_SYNCNT;

    case H_TCP_LINGER2:
        return TCP_LINGER2;

    case H_TCP_DEFER_ACCEPT:
        return TCP_DEFER_ACCEPT;

    case H_TCP_WINDOW_CLAMP:
        return TCP_WINDOW_CLAMP;

    case H_TCP_INFO:
        return TCP_INFO;

    case H_TCP_QUICKACK:
        return TCP_QUICKACK;

    case H_TCP_CONGESTION:
        return TCP_CONGESTION;

    case H_TCP_MD5SIG:
        return TCP_MD5SIG;

    case H_TCP_COOKIE_TRANSACTIONS:
        return TCP_COOKIE_TRANSACTIONS;

    case H_TCP_THIN_LINEAR_TIMEOUTS:
        return TCP_THIN_LINEAR_TIMEOUTS;

    case H_TCP_THIN_DUPACK:
        return TCP_THIN_DUPACK;

    case H_TCP_USER_TIMEOUT:
        return TCP_USER_TIMEOUT;

    case H_TCP_REPAIR:
        return TCP_REPAIR;

    case H_TCP_REPAIR_QUEUE:
        return TCP_REPAIR_QUEUE;

    case H_TCP_QUEUE_SEQ:
        return TCP_QUEUE_SEQ;

    case H_TCP_REPAIR_OPTIONS:
        return TCP_REPAIR_OPTIONS;

    case H_TCP_FASTOPEN:
        return TCP_FASTOPEN;

    case H_TCP_TIMESTAMP:
        return TCP_TIMESTAMP;

    case H_TCP_NOTSENT_LOWAT:
        return TCP_NOTSENT_LOWAT;

    case H_TCP_CC_INFO:
        return TCP_CC_INFO;

    case H_TCP_SAVE_SYN:
        return TCP_SAVE_SYN;

    case H_TCP_SAVED_SYN:
        return TCP_SAVED_SYN;

    case H_TCP_REPAIR_WINDOW:
        return TCP_REPAIR_WINDOW;

    case H_TCP_FASTOPEN_CONNECT:
        return TCP_FASTOPEN_CONNECT;

    case H_TCP_ULP:
        return TCP_ULP;

    case H_TCP_MD5SIG_EXT:
        return TCP_MD5SIG_EXT;

    case H_UDP_CORK:
        return UDP_CORK;

    case H_UDP_ENCAP:
        return UDP_ENCAP;

    case H_UDP_NO_CHECK6_TX:
        return UDP_NO_CHECK6_TX;

    case H_UDP_NO_CHECK6_RX:
        return UDP_NO_CHECK6_RX;
    
    default:
        return -1;
    }
}

char *sock_prop(char *str)
{
    char *level, *optname, *res;
    int l, n;

    if (!strtok(str, "/")) {
        return NULL;
    }
    level = strtok(NULL, "/");
    if (!level) {
        return NULL;
    }
    optname = strtok(NULL, "");
    if (!optname) {
        return NULL;
    }

    if(isnumeric(level)) {
        l = atoi(level);
    }
    else {
        l = get_socket_level(level);
        if (l < 0) {
            return NULL;
        }
    }

    if(isnumeric(optname)) {
        n = atoi(optname);
    }
    else {
        n = get_optname(optname);
        if (n < 0) {
            return NULL;
        }
    }

    res = malloc(20 * sizeof(char));
    snprintf(res, 20, "SO/%d/%d", l, n);
    return res;
}