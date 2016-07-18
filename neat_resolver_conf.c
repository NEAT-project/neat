#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "neat_resolver_conf.h"
#include "neat_internal.h"
#include "neat_queue.h"
#include "neat_addr.h"
#include "neat_resolver.h"

static void neat_resolver_reset_mark(struct neat_resolver *resolver)
{
    struct neat_resolver_server *server = resolver->server_list.lh_first;

    for (; server != NULL; server = server->next_server.le_next) {
        if (server->mark != NEAT_RESOLVER_SERVER_STATIC)
            server->mark = NEAT_RESOLVER_SERVER_DELETE;
    }
}

static void neat_resolver_delete_servers(struct neat_resolver *resolver)
{
    struct neat_resolver_server *server = resolver->server_list.lh_first;
    struct neat_resolver_server *server_to_delete;
    char dst_addr_buf[INET6_ADDRSTRLEN];
    struct sockaddr_in *server_addr4;
    struct sockaddr_in6* server_addr6;

    while (server != NULL) {
        if (server->mark != NEAT_RESOLVER_SERVER_DELETE) {
            server = server->next_server.le_next;
            continue;
        }

        server_to_delete = server;
        server = server->next_server.le_next;

        if (server_to_delete->server_addr.ss_family == AF_INET) {
            server_addr4 = (struct sockaddr_in*) &(server_to_delete->server_addr);
            inet_ntop(AF_INET, &(server_addr4->sin_addr), dst_addr_buf, INET6_ADDRSTRLEN);
        } else {
            server_addr6 = (struct sockaddr_in6*) &(server_to_delete->server_addr);
            inet_ntop(AF_INET6, &(server_addr6->sin6_addr), dst_addr_buf, INET6_ADDRSTRLEN);
        }

        LIST_REMOVE(server_to_delete, next_server);
        free(server_to_delete);

        neat_log(NEAT_LOG_INFO, "Deleted address %s from DNS list", dst_addr_buf);
    }
}

static void neat_resolver_resolv_check_addr(struct neat_resolver *resolver,
                                            struct sockaddr_storage *dst_addr)
{
    struct neat_resolver_server *server;
    struct sockaddr_in *dst_addr4, *server_addr4;
    struct sockaddr_in6 *dst_addr6, *server_addr6;
    uint8_t addr_equal = 0;
    char dst_addr_buf[INET6_ADDRSTRLEN];

    for (server = resolver->server_list.lh_first; server != NULL;
            server = server->next_server.le_next)
    {
        if (server->server_addr.ss_family != dst_addr->ss_family)
            continue;

        if (dst_addr->ss_family == AF_INET) {
            dst_addr4 = (struct sockaddr_in*) dst_addr;
            server_addr4 = (struct sockaddr_in*) &(server->server_addr);
            addr_equal = (dst_addr4->sin_addr.s_addr == server_addr4->sin_addr.s_addr);
            inet_ntop(AF_INET, &(dst_addr4->sin_addr), dst_addr_buf, INET6_ADDRSTRLEN);
        } else {
            dst_addr6 = (struct sockaddr_in6*) dst_addr;
            server_addr6 = (struct sockaddr_in6*) &(server->server_addr);
            addr_equal = neat_addr_cmp_ip6_addr(&(dst_addr6->sin6_addr),
                                                &(server_addr6->sin6_addr));
            inet_ntop(AF_INET6, &(dst_addr6->sin6_addr), dst_addr_buf, INET6_ADDRSTRLEN);
        }

        if (addr_equal) {
            neat_log(NEAT_LOG_INFO, "Addr %s found in resolver list", dst_addr_buf);
            server->mark = NEAT_RESOLVER_SERVER_ACTIVE;
            return;
        }
    }

    //TODO: Decide how to handle this error!
    if (!(server = calloc(sizeof(struct neat_resolver_server), 1))) {
        neat_log(NEAT_LOG_ERROR, "Failed to allocate memory for DNS server");
        return;
    }

    server->server_addr = *dst_addr;
    server->mark = NEAT_RESOLVER_SERVER_ACTIVE;
    LIST_INSERT_HEAD(&(resolver->server_list), server, next_server);

    if (dst_addr->ss_family == AF_INET) {
        dst_addr4 = (struct sockaddr_in*) dst_addr;
        inet_ntop(AF_INET, &(dst_addr4->sin_addr), dst_addr_buf, INET6_ADDRSTRLEN);
    } else {
        dst_addr6 = (struct sockaddr_in6*) dst_addr;
        inet_ntop(AF_INET6, &(dst_addr6->sin6_addr), dst_addr_buf, INET6_ADDRSTRLEN);
    }

    neat_log(NEAT_LOG_INFO, "Added %s to resolver list", dst_addr_buf);
}

void neat_resolver_resolv_conf_updated(uv_fs_event_t *handle,
        const char *filename, int events, int status)
{
    struct neat_resolver *resolver = handle->data;
    char nameserver_str[1024] = {0};
    char resolv_path[1024];
    size_t resolv_path_len = sizeof(resolv_path);
    FILE *resolv_ptr = NULL;
    char *resolv_line = NULL, *token = NULL;
    struct sockaddr_storage server_addr;
    struct sockaddr_in *server_addr4 = (struct sockaddr_in*) &server_addr;
    struct sockaddr_in6 *server_addr6 = (struct sockaddr_in6*) &server_addr;
    int retval;

    if (!(events & UV_CHANGE))
        return;

    memset(resolv_path, 0, resolv_path_len);
    if (uv_fs_event_getpath(handle, resolv_path, &resolv_path_len)) {
        neat_log(NEAT_LOG_WARNING, "Could not store resolv.conf path in buffer");
        return;
    }

    //TODO: Read filename dynamically
    if (!(resolv_ptr = fopen(resolv_path, "r"))) {
        neat_log(NEAT_LOG_WARNING, "Failed to open resolv-file");
        return;
    }

    //Mark all nameservers as ready to delete
    neat_resolver_reset_mark(resolver);

    while ((resolv_line = fgets(nameserver_str, sizeof(nameserver_str),
                                resolv_ptr))) {
        if (ferror(resolv_ptr)) {
            neat_log(NEAT_LOG_ERROR, "Failed to read line from resolv-file");
            //Reason for break and not return is that we might have got SOME
            //useful information from resolv.conf
            break;
        }

        //Takes care of newline and other weirdness at the start, so give the
        //first word on line
        token = strtok(resolv_line, " \t\r\n");

        if (!token)
            continue;

        if (strcmp(token, "nameserver") && strcmp(token, "server"))
            continue;

        if (!(token = strtok(NULL, " \t\r\n")))
            continue;

        //Parse IP, check if server is seen and add server to list if not
        retval = inet_pton(AF_INET, token, &(server_addr4->sin_addr));

        if (retval) {
            server_addr4->sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
            server_addr4->sin_len = sizeof(struct sockaddr_in);
#endif
            neat_resolver_resolv_check_addr(resolver, &server_addr);
            continue;
        }

        retval = inet_pton(AF_INET6, token, &(server_addr6->sin6_addr));

        if (retval) {
            server_addr6->sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
            server_addr6->sin6_len = sizeof(struct sockaddr_in6);
#endif
            neat_resolver_resolv_check_addr(resolver, &server_addr);
            continue;
        } else {
            neat_log(NEAT_LOG_ERROR, "Could not parse server %s", token);
        }
    }

    //Delete servers that have not been updated
    neat_resolver_delete_servers(resolver);
    fclose(resolv_ptr);
}

uint8_t neat_resolver_add_initial_servers(struct neat_resolver *resolver)
{
    struct neat_resolver_server *server;
    struct sockaddr_storage server_addr;
    struct sockaddr_in *addr4 = (struct sockaddr_in*) &server_addr;
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6*) &server_addr;
    uint16_t i = 0;

    LIST_INIT(&(resolver->server_list));

    for (i = 0; i < (sizeof(INET_DNS_SERVERS) / sizeof(const char*)); i++) {
        memset(addr4, 0, sizeof(struct sockaddr_in));
        addr4->sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
        addr4->sin_len = sizeof(struct sockaddr_in);
#endif
        inet_pton(AF_INET, INET_DNS_SERVERS[i], &(addr4->sin_addr));

        if (!(server = calloc(sizeof(struct neat_resolver_server), 1))) {
            neat_log(NEAT_LOG_ERROR, "Failed to allocate memory for DNS server");
            return 0;
        }

        server->server_addr = server_addr;
        server->mark = NEAT_RESOLVER_SERVER_STATIC;
        LIST_INSERT_HEAD(&(resolver->server_list), server, next_server);
    }

    for (i = 0; i < (sizeof(INET6_DNS_SERVERS) / sizeof(const char*)); i++) {
        memset(addr6, 0, sizeof(struct sockaddr_in6));
        addr6->sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
        addr6->sin6_len = sizeof(struct sockaddr_in6);
#endif
        inet_pton(AF_INET, INET6_DNS_SERVERS[i], &(addr6->sin6_addr));

        if (!(server = calloc(sizeof(struct neat_resolver_server), 1))) {
            neat_log(NEAT_LOG_ERROR, "Failed to allocate memory for DNS server");
            return 0;
        }

        server->server_addr = server_addr;
        server->mark = NEAT_RESOLVER_SERVER_STATIC;
        LIST_INSERT_HEAD(&(resolver->server_list), server, next_server);
    }

    neat_resolver_resolv_conf_updated(&(resolver->resolv_conf_handle), NULL,
                                      UV_CHANGE, 0);
    return 1;
}
