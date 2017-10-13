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

#ifndef NEAT_SOCKETAPI_H
#define NEAT_SOCKETAPI_H


#include <inttypes.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <neat.h>


typedef uint32_t neat_assoc_t;
typedef uint16_t neat_stream_t;


#define NEAT_UNDEFINED 0

#define NEAT_INIT 1
struct neat_initmsg {
   uint16_t sinit_num_ostreams;
   uint16_t sinit_max_instreams;
   uint16_t sinit_max_attempts;
   uint16_t sinit_max_init_timeo;
};

#define NEAT_SNDRCV 2
struct neat_sndrcvinfo
{
   uint16_t     sinfo_stream;
   uint16_t     sinfo_ssn;
   uint32_t     sinfo_flags;
   uint32_t     sinfo_ppid;
   uint32_t     sinfo_context;
   uint32_t     sinfo_timetolive;
   uint32_t     sinfo_tsn;
   uint32_t     sinfo_cumtsn;
   neat_assoc_t sinfo_assoc_id;
};

#define NEAT_ASSOC_CHANGE 1
struct neat_assoc_change
{
   uint16_t     sac_type;
   uint16_t     sac_flags;
   uint32_t     sac_length;
   uint16_t     sac_state;
   uint16_t     sac_error;
   uint16_t     sac_outbound_streams;
   uint16_t     sac_inbound_streams;
   neat_assoc_t sac_assoc_id;
};
#define NEAT_COMM_UP        11
#define NEAT_COMM_LOST      12
#define NEAT_RESTART        13
#define NEAT_SHUTDOWN_COMP  14
#define NEAT_CANT_STR_ASSOC 15

#define NEAT_PEER_ADDR_CHANGE 2
struct neat_paddr_change
{
    uint16_t                spc_type;
    uint16_t                spc_flags;
    uint32_t                spc_length;
    struct sockaddr_storage spc_aaddr;
    int                     spc_state;
    int                     spc_error;
    neat_assoc_t            spc_assoc_id;
};
#define NEAT_ADDR_REACHABLE   21
#define NEAT_ADDR_UNREACHABLE 22
#define NEAT_ADDR_REMOVED     23
#define NEAT_ADDR_ADDED       24
#define NEAT_ADDR_MADE_PRIM   25
#define NEAT_ADDR_CONFIRMED   26

#define NEAT_REMOTE_ERROR 3
struct neat_remote_error
{
   uint16_t     sre_type;
   uint16_t     sre_flags;
   uint32_t     sre_length;
   uint16_t     sre_error;
   neat_assoc_t sre_assoc_id;
   uint8_t      sre_data[32];
};

#define NEAT_SEND_FAILED 4
struct neat_send_failed
{
   uint16_t               ssf_type;
   uint16_t               ssf_flags;
   uint32_t               ssf_length;
   uint32_t               ssf_error;
   struct neat_sndrcvinfo ssf_info;
   neat_assoc_t           ssf_assoc_id;
   uint8_t                ssf_data[32];
};
#define NEAT_DATA_UNSENT 41
#define NEAT_DATA_SENT   42


#define NEAT_SHUTDOWN_EVENT 5
struct neat_shutdown_event
{
   uint16_t     sse_type;
   uint16_t     sse_flags;
   uint32_t     sse_length;
   neat_assoc_t sse_assoc_id;
};


#define NEAT_ADAPTATION_INDICATION 6
struct neat_adaptation_event
{
   uint16_t     sai_type;
   uint16_t     sai_flags;
   uint32_t     sai_length;
   uint32_t     sai_adaptation_ind;
   neat_assoc_t sai_assoc_id;
};


#define NEAT_PARTIAL_DELIVERY_EVENT 7
#define NEAT_PARTIAL_DELIVERY_ABORTED 1
struct neat_pdapi_event
{
   uint16_t     pdapi_type;
   uint16_t     pdapi_flags;
   uint32_t     pdapi_length;
   uint32_t     pdapi_indication;
   neat_assoc_t pdapi_assoc_id;
};


/*
   For interal implementation usage only!
 */
#define NEAT_DATA_ARRIVE 8
#define NEAT_ARRIVE_UNORDERED (1 << 0)
struct neat_data_arrive
{
   uint16_t      sda_type;
   uint16_t      sda_flags;
   uint32_t      sda_length;
   neat_assoc_t  sda_assoc_id;
   neat_stream_t sda_stream;
   uint32_t      sda_ppid;
   uint32_t      sda_bytes_arrived;
};


union neat_notification {
   struct {
      uint16_t nnh_type;
      uint16_t nnh_flags;
      uint32_t nnh_length;
   }                            nn_header;

   struct neat_assoc_change     nn_assoc_change;
   struct neat_paddr_change     nn_paddr_change;
   struct neat_remote_error     nn_remote_error;
   struct neat_send_failed      nn_send_failed;
   struct neat_shutdown_event   nn_shutdown_event;
   struct neat_adaptation_event nn_adaptation_event;
   struct neat_pdapi_event      nn_pdapi_event;

   struct neat_data_arrive      nn_data_arrive;
};


#ifdef __cplusplus
extern "C" {
#endif

/* ====== Initialisation and Clean-Up ==================================== */
int nsa_init();
void nsa_cleanup();
int nsa_map_socket(int systemSD, int neatSD);
int nsa_unmap_socket(int neatSD);

/* ====== Connection Establishment and Teardown ========================== */
int nsa_socket(int domain, int type, int protocol, const char* properties);
int nsa_socketpair(int domain, int type, int protocol, int sv[2], const char* properties);
int nsa_close(int sockfd);
int nsa_fcntl(int sockfd, int cmd, ...);
int nsa_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen,
             struct neat_tlv* opt, const int optcnt);
int nsa_bindx(int sockfd, const struct sockaddr* addrs, int addrcnt, int flags,
              struct neat_tlv* opt, const int optcnt);
int nsa_bindn(int sockfd, uint16_t port, int flags,
              struct neat_tlv* opt, const int optcnt);
int nsa_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen,
                struct neat_tlv* opt, const int optcnt);
int nsa_connectx(int sockfd, const struct sockaddr* addrs, int addrcnt, neat_assoc_t* id,
                 struct neat_tlv* opt, const int optcnt);
int nsa_connectn(int sockfd, const char* name, const uint16_t port, neat_assoc_t* id,
                 struct neat_tlv* opt, const int optcnt);
int nsa_listen(int sockfd, int backlog);
int nsa_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen);
int nsa_peeloff(int sockfd, neat_assoc_t id);
int nsa_shutdown(int sockfd, int how);

/* ====== Options Handling =============================================== */
int nsa_getsockopt(int sockfd, int level,
                   int optname, void* optval, socklen_t* optlen);
int nsa_setsockopt(int sockfd, int level,
                   int optname, const void* optval, socklen_t optlen);
int nsa_opt_info(int sockfd, neat_assoc_t id,
                 int opt, void* arg, socklen_t* size);

/* ====== Security ======================================================= */
int nsa_set_secure_identity(int sockfd, const char* pem);

/* ====== Input/Output Handling ========================================== */
ssize_t nsa_write(int fd, const void* buf, size_t len);
ssize_t nsa_send(int sockfd, const void* buf, size_t len, int flags);
ssize_t nsa_sendto(int sockfd, const void* buf, size_t len, int flags,
                   const struct sockaddr* to, socklen_t tolen);
ssize_t nsa_sendmsg(int sockfd, const struct msghdr* msg, int flags);
ssize_t nsa_sendv(int sockfd, struct iovec* iov, int iovcnt,
                  struct sockaddr* to, int tocnt,
                  void* info, socklen_t infolen, unsigned int infotype,
                  int flags);

ssize_t nsa_read(int fd, void* buf, size_t len);
ssize_t nsa_recv(int sockfd, void* buf, size_t len, int flags);
ssize_t nsa_recvfrom(int sockfd, void* buf, size_t len, int flags,
                     struct sockaddr* from, socklen_t* fromlen);
ssize_t nsa_recvmsg(int sockfd, struct msghdr* msg, int flags);
ssize_t nsa_recvv(int sockfd, struct iovec* iov, int iovcnt,
                  struct sockaddr* from, socklen_t* fromlen,
                  void* info, socklen_t* infolen, unsigned int* infotype,
                  int* msg_flags);

/* ====== Poll and Select ================================================ */
int nsa_poll(struct pollfd* ufds, const nfds_t nfds, int timeout);
int nsa_select(int n, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
               struct timeval* timeout);
int nsa_epoll_create(int size);
int nsa_epoll_create1(int flags);
int nsa_epoll_ctl(int epfd, int op, int fd, struct epoll_event* event);
int nsa_epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout);
int nsa_epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
                    int timeout, const sigset_t* ss);

/* ====== Address Handling =============================================== */
int nsa_getsockname(int sockfd, struct sockaddr* name, socklen_t* namelen);
int nsa_getpeername(int sockfd, struct sockaddr* name, socklen_t* namelen);
int nsa_getladdrs(int sockfd, neat_assoc_t id, struct sockaddr** addrs);
void nsa_freeladdrs(struct sockaddr* addrs);
int nsa_getpaddrs(int sockfd, neat_assoc_t id, struct sockaddr** addrs);
void nsa_freepaddrs(struct sockaddr* addrs);

/* ====== Miscellaneous ================================================== */
int nsa_open(const char* pathname, int flags, ...);
int nsa_creat(const char* pathname, mode_t mode);
off_t nsa_lseek(int fd, off_t offset, int whence);
int nsa_ftruncate(int fd, off_t length);
#ifdef _LARGEFILE64_SOURCE
off64_t nsa_lseek64(int fd, off64_t offset, int whence);
int nsa_ftruncate64(int fd, off64_t length);
#endif
int nsa_pipe(int fds[2]);
int nsa_ioctl(int fd, int request, const void* argp);

#ifdef __cplusplus
}
#endif

#endif
