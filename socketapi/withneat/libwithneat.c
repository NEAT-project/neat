/*
 * Socket API implementation for NEAT
 * Copyright (C) 2016-2017 by Thomas Dreibholz <dreibh@simula.no>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of NEAT nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <neat-socketapi.h>

#define DEBUG(name, x) \
   printf("debug: %s %lld\n", #name, (long long)x)

#define DEF1(rt, name,t1) \
   rt name(t1 a) { DEBUG(name, a); return(nsa_##name(a)); }
#define DEF2(rt, name, t1, t2) \
   rt name(t1 a, t2 b) { DEBUG(name, a); return(nsa_##name(a, b)); }
#define DEF3(rt, name, t1, t2, t3) \
   rt name(t1 a, t2 b, t3 c) { DEBUG(name, a); return(nsa_##name(a, b, c)); }
#define DEF4(rt, name, t1, t2, t3, t4) \
   rt name(t1 a, t2 b, t3 c, t4 d) { DEBUG(name, a); return(nsa_##name(a, b, c, d)); }
#define DEF5(rt, name, t1, t2, t3, t4, t5) \
   rt name(t1 a, t2 b, t3 c, t4 d, t5 e) { DEBUG(name, a); return(nsa_##name(a, b, c, d, e)); }
#define DEF6(rt, name, t1, t2, t3, t4, t5, t6) \
   rt name(t1 a, t2 b, t3 c, t4 d, t5 e, t6 f) { DEBUG(name, a); return(nsa_##name(a, b, c, d, e, f)); }
#define DEF9(rt, name, t1, t2, t3, t4, t5, t6, t7, t8, t9) \
   rt name(t1 a, t2 b, t3 c, t4 d, t5 e, t6 f, t7 g, t8 h, t9 i) { DEBUG(name, a); return(nsa_##name(a, b, c, d, e, f, g, h, i)); }


/* ====== Connection Establishment and Teardown ========================== */
int socket(int domain, int type, int protocol)
{
   return(nsa_socket(domain, type, protocol, NULL));
}

DEF1(int, close, int)

int bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{ return(nsa_bind(sockfd, addr, addrlen, NULL, 0)); }

int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{ return(nsa_bind(sockfd, addr, addrlen, NULL, 0)); }

DEF2(int, listen, int, int)
DEF3(int, accept, int, struct sockaddr*, socklen_t*)
// int peeloff(int sockfd, neat_assoc_t id);
DEF2(int, shutdown, int, int)

/* ====== Options Handling =============================================== */
DEF5(int, getsockopt, int, int, int, void*, socklen_t*)
DEF5(int, setsockopt, int, int, int, const void*, socklen_t)

/* ====== Input/Output Handling ========================================== */
DEF3(ssize_t, write, int, const void*, size_t)
DEF4(ssize_t, send, int, const void*, size_t, int)
DEF6(ssize_t, sendto, int, const void*, size_t, int, const struct sockaddr*, socklen_t)
DEF3(ssize_t, sendmsg, int, const struct msghdr*, int)
DEF9(ssize_t, sendv, int, struct iovec*, int, struct sockaddr*, int, void*, socklen_t, unsigned int, int)

DEF3(ssize_t, read, int, void*, size_t)
DEF4(ssize_t, recv, int, void*, size_t, int)
DEF6(ssize_t, recvfrom, int, void*, size_t, int, struct sockaddr*, socklen_t*)
DEF3(ssize_t, recvmsg, int, struct msghdr*, int)
DEF9(ssize_t, recvv, int, struct iovec*, int, struct sockaddr*, socklen_t*, void*, socklen_t*, unsigned int*, int*)

/* ====== Poll and Select ================================================ */
DEF3(int, poll, struct pollfd*, const nfds_t, int)
DEF5(int, select,int, fd_set*, fd_set*, fd_set*, struct timeval*)

/* ====== Address Handling =============================================== */
DEF3(int, getsockname, int, struct sockaddr*, socklen_t*)
DEF3(int, getpeername, int, struct sockaddr*, socklen_t*)
/*
int getladdrs(int sockfd, neat_assoc_t id, struct sockaddr** addrs);
void freeladdrs(struct sockaddr* addrs);
int getpaddrs(int sockfd, neat_assoc_t id, struct sockaddr** addrs);
void freepaddrs(struct sockaddr* addrs);
*/

/* ====== Miscellaneous ================================================== */
int open(const char* pathname, int flags, ...)
{   
   va_list args;
   va_start(args, flags);
   int result = nsa_open(pathname, flags, __builtin_va_arg_pack());
   va_end(args);
   return(result);
}

DEF2(int, creat, const char*, mode_t)
int pipe(int fds[2]) { return(nsa_pipe(fds)); }
DEF3(int, ioctl, int, int, const void*)
