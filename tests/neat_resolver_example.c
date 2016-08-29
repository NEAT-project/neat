#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "../neat.h"

// The resolver interface is internal - but this is still a good test
#include "../neat_internal.h"

//HACKHACKHACK, code is not supposed to access resolver directly
#include "../neat_resolver.h"

// clang -g neat_resolver_example.c ../build/libneatS.a -luv -lldns -lmnl
// or if you have installed neat globally
// clang -g neat_resolver_example.c -lneat

static uint8_t expected_replies;
static uint8_t num_replies;

static neat_error_code resolver_handle(struct neat_resolver_results *results,
                                       uint8_t neat_code,
                                       void *user_data)
{
    char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
    struct neat_resolver_res *result;
    struct neat_resolver *resolver = user_data;

    num_replies++;

    if (neat_code != NEAT_RESOLVER_OK) {
        fprintf(stderr, "Resolver failed\n");

        if (num_replies == expected_replies)
            neat_stop_event_loop(resolver->nc);
        return NEAT_ERROR_DNS;
    }

    LIST_FOREACH(result, results, next_res) {
        getnameinfo((struct sockaddr *)&result->src_addr, result->src_addr_len,
                    src_str, sizeof(src_str), NULL, 0,
                    NI_NUMERICHOST);
        getnameinfo((struct sockaddr *)&result->dst_addr, result->dst_addr_len,
                    dst_str, sizeof(dst_str), NULL, 0,
                    NI_NUMERICHOST);

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

        printf(": %s -> %s\n", src_str, dst_str);
    }

    //Free list, it is callers responsibility
    neat_resolver_free_results(results);
    //neat_resolver_release(resolver);
    if (num_replies == expected_replies)
        neat_stop_event_loop(resolver->nc);

    return NEAT_ERROR_OK;
}

static void resolver_cleanup(struct neat_resolver *resolver)
{
    printf("Cleanup function\n");
    //I dont need this resolver object any more
    neat_resolver_release(resolver);
}

static uint8_t test_resolver(struct neat_resolver *resolver,
                             uint8_t family,
                             char *node,
                             uint16_t port)
{
    if (neat_resolve(resolver, family, node, port, resolver_handle, resolver))
        return 1;
    else
        return 0;
}

static void test_single_request_v4(struct neat_ctx *nc,
                                   struct neat_resolver *resolver)
{
    test_resolver(resolver, AF_INET, "www.google.com", 80);
    expected_replies = 1;
    num_replies = 0;
    neat_start_event_loop(nc, NEAT_RUN_DEFAULT);
    test_resolver(resolver, AF_INET, "www.facebook.com", 80);
    expected_replies = 1;
    num_replies = 0;
    neat_start_event_loop(nc, NEAT_RUN_DEFAULT);
    test_resolver(resolver, AF_INET, "www.vg.no", 80);
    expected_replies = 1;
    num_replies = 0;
    neat_start_event_loop(nc, NEAT_RUN_DEFAULT);
}

static void test_single_request_literal_v4(struct neat_ctx *nc,
                                           struct neat_resolver *resolver)
{
    test_resolver(resolver, AF_INET, "127.0.0.1", 80);
    expected_replies = 1;
    num_replies = 0;
    neat_start_event_loop(nc, NEAT_RUN_DEFAULT);
    test_resolver(resolver, AF_INET, "8.8.8.8", 80);
    expected_replies = 1;
    num_replies = 0;
    neat_start_event_loop(nc, NEAT_RUN_DEFAULT);
    test_resolver(resolver, AF_INET, "8.8.4.4", 80);
    expected_replies = 1;
    num_replies = 0;
    neat_start_event_loop(nc, NEAT_RUN_DEFAULT);
}

static void test_single_request_v6(struct neat_ctx *nc,
                                   struct neat_resolver *resolver)
{
    test_resolver(resolver, AF_INET6, "www.google.com", 80);
    expected_replies = 1;
    num_replies = 0;
    neat_start_event_loop(nc, NEAT_RUN_DEFAULT);
    test_resolver(resolver, AF_INET6, "www.facebook.com", 80);
    expected_replies = 1;
    num_replies = 0;
    neat_start_event_loop(nc, NEAT_RUN_DEFAULT);
    test_resolver(resolver, AF_INET6, "www.vg.no", 80);
    expected_replies = 1;
    num_replies = 0;
    neat_start_event_loop(nc, NEAT_RUN_DEFAULT);
}

static void test_parallel_requests_v4(struct neat_ctx *nc,
                                   struct neat_resolver *resolver)
{
    test_resolver(resolver, AF_INET, "www.google.com", 80);
    test_resolver(resolver, AF_INET, "www.facebook.com", 80);
    test_resolver(resolver, AF_INET, "www.vg.no", 80);
    expected_replies = 3;
    num_replies = 0;
    neat_start_event_loop(nc, NEAT_RUN_DEFAULT);
}

static void test_parallel_requests_literal_v4(struct neat_ctx *nc,
                                              struct neat_resolver *resolver)
{
    test_resolver(resolver, AF_INET, "www.google.com", 80);
    test_resolver(resolver, AF_INET, "127.0.0.1", 80);
    test_resolver(resolver, AF_INET, "www.facebook.com", 80);
    test_resolver(resolver, AF_INET, "8.8.8.8", 80);
    test_resolver(resolver, AF_INET, "www.vg.no", 80);
    test_resolver(resolver, AF_INET, "8.8.4.4", 80);
    expected_replies = 6;
    num_replies = 0;
    neat_start_event_loop(nc, NEAT_RUN_DEFAULT);
}

static void test_parallel_requests_v6(struct neat_ctx *nc,
                                   struct neat_resolver *resolver)
{
    test_resolver(resolver, AF_INET6, "www.google.com", 80);
    test_resolver(resolver, AF_INET6, "www.facebook.com", 80);
    test_resolver(resolver, AF_INET6, "www.vg.no", 80);
    expected_replies = 3;
    num_replies = 0;
    neat_start_event_loop(nc, NEAT_RUN_DEFAULT);
}

static void test_parallel_requests_mixed(struct neat_ctx *nc,
                                         struct neat_resolver *resolver)
{
    test_resolver(resolver, AF_INET, "www.google.com", 80);
    test_resolver(resolver, AF_INET6, "www.google.com", 80);
    test_resolver(resolver, AF_INET, "www.facebook.com", 80);
    test_resolver(resolver, AF_INET6, "www.facebook.com", 80);
    test_resolver(resolver, AF_INET, "www.vg.no", 80);
    test_resolver(resolver, AF_INET6, "www.vg.no", 80);
    expected_replies = 6;
    num_replies = 0;
    neat_start_event_loop(nc, NEAT_RUN_DEFAULT);
}

int main(int argc, char *argv[])
{
    struct neat_ctx *nc = neat_init_ctx();
    struct neat_resolver *resolver;

    resolver = nc ? neat_resolver_init(nc, "/etc/resolv.conf") : NULL;

    if (nc == NULL || resolver == NULL)
        exit(EXIT_FAILURE);

    //this is set in he_lookup in the other example code
    nc->resolver = resolver;
    neat_resolver_update_timeouts(resolver, 5000, 500);

    test_single_request_v4(nc, resolver);
    test_single_request_literal_v4(nc, resolver);
    //test_single_request_v6(nc, resolver);
    test_parallel_requests_v4(nc, resolver);
    test_parallel_requests_literal_v4(nc, resolver);
    //test_parallel_requests_v6(nc, resolver);
    //test_parallel_requests_mixed(nc, resolver);
    neat_free_ctx(nc);
    exit(EXIT_SUCCESS);
}
