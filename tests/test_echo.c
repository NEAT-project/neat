#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


int
test_protocol(int protocol, int socktype)
{
    int rc, sock;
    struct addrinfo *info, hints;
    char buffer[5];

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_family = AF_INET;
    hints.ai_socktype = socktype;
    hints.ai_protocol = protocol;

    rc = getaddrinfo("localhost", "8080", &hints, &info);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo failed - %s", gai_strerror(rc));
        return -1;
    }

    sock = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    rc = connect(sock, info->ai_addr, info->ai_addrlen);
    if (rc < 0) {
        perror("connect");
        return -1;
    }

    rc = send(sock, "TEST", 4, MSG_WAITALL);
    if (rc != 4) {
        perror("send");
        return -1;
    }

    rc = recv(sock, buffer, 4, MSG_WAITALL);
    if (rc != 4) {
        perror("recv");
        return -1;
    }

    buffer[4] = 0;

    if (strcmp(buffer, "TEST") != 0) {
        fprintf(stderr, "Expected \"TEST\", received: \"%s\"\n", buffer);
        return -1;
    }

    close(sock);

    freeaddrinfo(info);

    return 0;
}

int
main(int argc, char *argv[])
{
    int rc = 0;

    printf("Testing TCP\n");
    if (test_protocol(IPPROTO_TCP, SOCK_STREAM)) {
        rc = -1;
    }
    printf("Testing UDP\n");
    if (test_protocol(IPPROTO_UDP, SOCK_DGRAM)) {
        rc = -1;
    }
#ifdef HAVE_NETINET_SCTP_H
    printf("Testing SCTP\n");
    if (test_protocol(IPPROTO_SCTP, SOCK_STREAM)) {
        rc = -1;
    }
#endif

#if defined(__FreeBSD__)
    // test_protocol(IPPROTO_UDPLITE, SOCK_DGRAM);
#endif

    return rc;
}
