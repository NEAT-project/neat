/*
 * Code for testing the DSCP failover mechanism.
 *
 * Compile:
 * gcc -Wall -fPIC -shared -o dscp_failover_preload.so dscp_failover_preload.c -ldl
 *
 * Run:
 * LD_PRELOAD=<neat_dir>/tests/dscp_failover_preload.so:/usr/lib/libuv.so [command]
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>

#include <netinet/in.h>

#define ORIGINAL_FUNC(name, retval, params...) \
    retval (*original_ ## name)(params); \
    original_## name = (retval (*)(params))dlsym(RTLD_NEXT, #name);

static int victim_fd = 0;

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
    ORIGINAL_FUNC(setsockopt, int, int, int, int, const void*, socklen_t);

    if (level != IPPROTO_IP)
        goto passthrough;

    if (optname != IP_TOS)
        goto passthrough;

    if (optval == NULL || *(int*)optval == 0)
        goto passthrough;

    fprintf(stderr, ">>> SETTING TOS TO 0x%x\n", *(int*)optval);

    victim_fd = sockfd;
    fprintf(stderr, ">>> VICTIM IS FD %d\n", victim_fd);

passthrough:
    return original_setsockopt(sockfd, level, optname, optval, optlen);
}

ssize_t recv(int sockfd, void* buf, size_t len, int flags)
{
    static int deploy_trap_in = 3;
    ORIGINAL_FUNC(recv, ssize_t, int, void*, size_t, int);

    if (victim_fd == 0 || sockfd != victim_fd)
        goto passthrough;

    if (deploy_trap_in && --deploy_trap_in)
        goto passthrough;

    // IT'S A TRAP!
    //      - Admiral Ackbar

    errno = ETIMEDOUT;
    return -1;
passthrough:
    return original_recv(sockfd, buf, len, flags);
}

int close(int sockfd)
{
    ORIGINAL_FUNC(close, int, int);
    if (victim_fd != 0 && sockfd == victim_fd)
        victim_fd = 0;

    return original_close(sockfd);
}
