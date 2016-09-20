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


void
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
        exit(EXIT_FAILURE);
    }

    sock = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    rc = connect(sock, info->ai_addr, info->ai_addrlen);
    if (rc < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    rc = send(sock, "TEST", 4, MSG_WAITALL);
    if (rc != 4) {
        perror("send");
        exit(EXIT_FAILURE);
    }

    rc = recv(sock, buffer, 4, MSG_WAITALL);
    if (rc != 4) {
        perror("recv");
        exit(EXIT_FAILURE);
    }

    buffer[4] = 0;

    if (strcmp(buffer, "TEST") != 0) {
        fprintf(stderr, "Expected \"TEST\", received: \"%s\"\n", buffer);
        exit(EXIT_FAILURE);
    }

    close(sock);

    freeaddrinfo(info);
}

int
main(int argc, char *argv[])
{
    printf("Testing TCP\n");
    test_protocol(IPPROTO_TCP, SOCK_STREAM);
    printf("Testing UDP\n");
    test_protocol(IPPROTO_UDP, SOCK_DGRAM);
#ifdef HAVE_NETINET_SCTP_H
    printf("Testing SCTP\n");
    test_protocol(IPPROTO_SCTP, SOCK_STREAM);
#endif

#if defined(__FreeBSD__)
    // test_protocol(IPPROTO_UDPLITE, SOCK_DGRAM);
#endif

    return 0;
}
