#ifndef NEAT_RESOLVER_HELPERS_H
#define NEAT_RESOLVER_HELPERS_H

#include <stdint.h>
#ifdef __linux__
    #include <netinet/in.h>
#elif _WIN32
    #include <inaddr.h>
    #include <in6addr.h>
#endif

//These are the private networks defined by IANA. We use them to check if we end
//up in the private network after following redirects
#define IANA_A_NW           0x0a000000 //10.0.0.0
#define IANA_A_MASK         0xff000000 //255.0.0.0 (8)
#define IANA_B_NW           0xac100000 //172.16.0.0
#define IANA_B_MASK         0xfff00000 //255.240.0.0 (12)
#define IANA_C_NW           0xc0a80000 //192.168.0.0
#define IANA_C_MASK         0xffff0000 //255.255.0.0 (16)

struct sockaddr_storage;
struct neat_resolver_results;
struct neat_addr;
struct neat_resolver_src_dst_addr;
struct neat_resolver_request;

uint8_t
neat_resolver_helpers_addr_internal(struct sockaddr_storage *addr);

int8_t
neat_resolver_helpers_check_for_literal(uint8_t *family,
                                        const char *node);

uint8_t
neat_resolver_helpers_fill_results(struct neat_resolver_request *request,
                                   struct neat_resolver_results *result_list,
                                   struct neat_addr *src_addr,
                                   struct sockaddr_storage dst_addr);

uint8_t
neat_resolver_helpers_check_duplicate(struct neat_resolver_src_dst_addr *pair,
                                      const char *resolved_addr_str);

#endif
