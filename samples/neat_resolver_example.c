#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "../neat.h"

// The resolver interface is internal - but this is still a good test
#include "../neat_internal.h"

// clang -g neat_resolver_example.c ../build/libneatS.a -luv -lldns -lmnl
// or if you have installed neat globally
// clang -g neat_resolver_example.c -lneat


void resolver_handle(struct neat_resolver *resolver,
                     struct neat_resolver_results *res, uint8_t neat_code)
{
    char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;
    struct neat_resolver_res *res_itr;

    if (neat_code != NEAT_RESOLVER_OK) {
        //For now res is always NULL when code is not OK, but keep this sanity
        //check here just in case
        if (res != NULL)
            neat_resolver_free_results(res);
        return;    
    }

    res_itr = res->lh_first;

    while (res_itr != NULL) {
        if (res_itr->ai_family == AF_INET) {
            addr4 = (struct sockaddr_in*) &(res_itr->src_addr);
            inet_ntop(res_itr->ai_family, &(addr4->sin_addr), src_str, INET_ADDRSTRLEN);
            addr4 = (struct sockaddr_in*) &(res_itr->dst_addr);
            inet_ntop(res_itr->ai_family, &(addr4->sin_addr), dst_str, INET_ADDRSTRLEN);
        } else {
            addr6 = (struct sockaddr_in6*) &(res_itr->src_addr);
            inet_ntop(res_itr->ai_family, &(addr6->sin6_addr), src_str, INET6_ADDRSTRLEN);
            addr6 = (struct sockaddr_in6*) &(res_itr->dst_addr);
            inet_ntop(res_itr->ai_family, &(addr6->sin6_addr), dst_str, INET6_ADDRSTRLEN);
        }
           
        printf("Family %u Socktype %u Protocol %u Src. %s Resolved to %s\n",
                res_itr->ai_family, res_itr->ai_socktype, res_itr->ai_protocol, src_str, dst_str);
        res_itr = res_itr->next_res.le_next;
    }

    //Free list, it is callers responsibility
    neat_resolver_free_results(res);
}

void resolver_cleanup(struct neat_resolver *resolver)
{
    printf("Cleanup function\n");
    //I dont need this resolver object any more
    neat_resolver_free(resolver);
}

int main(int argc, char *argv[])
{
    struct neat_ctx *nc = neat_init_ctx();
    struct neat_resolver *resolver;
    resolver = nc ? neat_resolver_init(nc, resolver_handle, resolver_cleanup) : NULL;

    if (nc == NULL || resolver == NULL)
        exit(EXIT_FAILURE);

    neat_resolver_update_timeouts(resolver, 10000, 500);

    //TODO: FIND A BETTER WAY OF TESTIN!
    /*if (neat_getaddrinfo(resolver, AF_UNSPEC, "www.google.com", "80", SOCK_DGRAM, IPPROTO_UDP))
        exit(EXIT_FAILURE);*/
    /*if (neat_getaddrinfo(resolver, AF_UNSPEC, "8.8.8.8", "80", SOCK_DGRAM, IPPROTO_UDP))
        exit(EXIT_FAILURE);*/
    /*if (neat_getaddrinfo(resolver, AF_INET6, "8.8.8.8", "80", SOCK_DGRAM, IPPROTO_UDP))
        exit(EXIT_FAILURE);*/
    /*if (neat_getaddrinfo(resolver, AF_INET, "2001:4860:4860::8888", "80", SOCK_DGRAM, IPPROTO_UDP))
        exit(EXIT_FAILURE);*/
    if (neat_getaddrinfo(resolver, AF_INET, "8.8.8.8", "80", SOCK_DGRAM, IPPROTO_UDP))
        exit(EXIT_FAILURE);
    /*if (neat_getaddrinfo(resolver, AF_INET6, "2001:4860:4860::8888", "80", SOCK_DGRAM, IPPROTO_UDP))
        exit(EXIT_FAILURE);*/

    neat_start_event_loop(nc);

    neat_free_ctx(nc);
    exit(EXIT_SUCCESS);
}
