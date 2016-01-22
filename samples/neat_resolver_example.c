#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "../neat.h"

// The resolver interface is internal - but this is still a good test
#include "../neat_internal.h"

// clang -g neat_resolver_example.c ../build/libneatS.a -luv -lldns -lmnl
// or if you have installed neat globally
// clang -g neat_resolver_example.c -lneat


static void resolver_handle(struct neat_resolver *resolver,
                     struct neat_resolver_results *results, uint8_t neat_code)
{
    char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
    struct neat_resolver_res *result;

    if (neat_code != NEAT_RESOLVER_OK) {
        fprintf(stderr, "Resolver failed\n");
        neat_stop_event_loop(resolver->nc);
        return;    
    }

    LIST_FOREACH(result, results, next_res) {
        getnameinfo((struct sockaddr *)&result->src_addr, result->src_addr_len,
                    src_str, sizeof(src_str), NULL, 0,
                    NI_NUMERICHOST);
        getnameinfo((struct sockaddr *)&result->dst_addr, result->dst_addr_len,
                    dst_str, sizeof(dst_str), NULL, 0,
                    NI_NUMERICHOST);
        switch (result->ai_protocol) {
        case IPPROTO_UDP:
            fprintf(stderr, "UDP/");
            break;
        case IPPROTO_TCP:
            fprintf(stderr, "TCP/");
            break;
        case IPPROTO_SCTP:
            fprintf(stderr, "SCTP/");
            break;
#ifdef IPPROTO_UDPLITE
        case IPPROTO_UDPLITE:
            fprintf(stderr, "UDP-LITE/");
            break;
#endif
        default:
            fprintf(stderr, "proto%d/", result->ai_protocol);
            break;
        }
        switch (result->ai_family) {
        case AF_INET:
            fprintf(stderr, "IPv4");
            break;
        case AF_INET6:
            fprintf(stderr, "IPv6");
            break;
        default:
            fprintf(stderr, "family%d", result->ai_family);
            break;
        }
        switch (result->ai_socktype) {
        case SOCK_DGRAM:
            fprintf(stderr, "[SOCK_DGRAM]");
            break;
        case SOCK_STREAM:
            fprintf(stderr, "[SOCK_STREAM]");
            break;
        case SOCK_SEQPACKET:
            fprintf(stderr, "[SOCK_SEQPACKET]");
            break;
        default:
            fprintf(stderr, "[%d]", result->ai_socktype);
            break;
        }
        printf(": %s -> %s\n", src_str, dst_str);
    }

    //Free list, it is callers responsibility
    neat_resolver_free_results(results);
    neat_stop_event_loop(resolver->nc);
}

static void resolver_cleanup(struct neat_resolver *resolver)
{
    printf("Cleanup function\n");
    //I dont need this resolver object any more
    neat_resolver_release(resolver);
}

static uint8_t test_resolver(struct neat_ctx *nc, struct neat_resolver *resolver,
        uint8_t family, int protocol[], uint8_t proto_count, char *node, char *service)
{
    if (neat_getaddrinfo(resolver, family, node, service, protocol, proto_count))
        return 1;

    neat_start_event_loop(nc, NEAT_RUN_DEFAULT);
    return 0;
}

int main(int argc, char *argv[])
{
    struct neat_ctx *nc = neat_init_ctx();
    struct neat_resolver *resolver;
    int32_t test_proto[NEAT_MAX_NUM_PROTO];

    resolver = nc ? neat_resolver_init(nc, resolver_handle, resolver_cleanup) : NULL;

    if (nc == NULL || resolver == NULL)
        exit(EXIT_FAILURE);

    memset(test_proto, 0, NEAT_MAX_NUM_PROTO * sizeof(int32_t));

    //this is set in he_lookup in the other example code
    nc->resolver = resolver;

    neat_resolver_update_timeouts(resolver, 5000, 500);
    test_proto[0] = IPPROTO_UDP;
    test_proto[1] = IPPROTO_TCP;
    test_proto[2] = IPPROTO_SCTP;
#ifdef IPPROTO_UDPLITE
    test_proto[3] = IPPROTO_UDPLITE;
#endif
#ifdef IPPROTO_UDPLITE
    test_resolver(nc, resolver, AF_INET, test_proto, 4, "www.google.com", "80");
#else
    test_resolver(nc, resolver, AF_INET, test_proto, 3, "www.google.com", "80");
#endif
    neat_resolver_reset(resolver);
#ifdef IPPROTO_UDPLITE
    test_resolver(nc, resolver, AF_INET6, test_proto, 4, "www.google.com", "80");
#else
    test_resolver(nc, resolver, AF_INET6, test_proto, 3, "www.google.com", "80");
#endif
    neat_resolver_reset(resolver);
#ifdef IPPROTO_UDPLITE
    test_resolver(nc, resolver, AF_INET, test_proto, 4, "www.facebook.com", "80");
#else
    test_resolver(nc, resolver, AF_INET, test_proto, 3, "www.facebook.com", "80");
#endif
    neat_resolver_reset(resolver);
#ifdef IPPROTO_UDPLITE
    test_resolver(nc, resolver, AF_INET6, test_proto, 4, "www.facebook.com", "80");
#else
    test_resolver(nc, resolver, AF_INET6, test_proto, 3, "www.facebook.com", "80");
#endif
    neat_resolver_reset(resolver);
    test_proto[0] = IPPROTO_TCP;
    test_resolver(nc, resolver, AF_INET, test_proto, 1, "bsd10.fh-muenster.de", "80");
    neat_resolver_reset(resolver);
    test_resolver(nc, resolver, AF_INET6, test_proto, 1, "bsd10.fh-muenster.de", "80");
    neat_resolver_reset(resolver);
    test_proto[0] = IPPROTO_SCTP;
    test_resolver(nc, resolver, AF_INET, test_proto, 1, "bsd10.fh-muenster.de", "80");
    neat_resolver_reset(resolver);
    test_resolver(nc, resolver, AF_INET6, test_proto, 1, "bsd10.fh-muenster.de", "80");
    neat_resolver_reset(resolver);

    test_proto[0] = IPPROTO_UDP;
    test_resolver(nc, resolver, AF_INET, test_proto, 1, "bsd10.fh-muenster.de", "80");
    neat_resolver_reset(resolver);
    test_resolver(nc, resolver, AF_INET6, test_proto, 1, "bsd10.fh-muenster.de", "80");
    neat_resolver_reset(resolver);
    test_resolver(nc, resolver, AF_UNSPEC, test_proto, 1, "bsd10.fh-muenster.de", "80");
 
    test_proto[0] = IPPROTO_TCP;
    test_proto[1] = IPPROTO_SCTP;
    neat_resolver_reset(resolver);
    test_resolver(nc, resolver, AF_INET, test_proto, 2, "bsd10.fh-muenster.de", "80");
    neat_resolver_reset(resolver);
    test_resolver(nc, resolver, AF_INET6, test_proto, 2, "bsd10.fh-muenster.de", "80");
    neat_resolver_reset(resolver);
    test_resolver(nc, resolver, AF_UNSPEC, test_proto, 2, "bsd10.fh-muenster.de", "80");
    
    neat_free_ctx(nc);
    exit(EXIT_SUCCESS);
}
