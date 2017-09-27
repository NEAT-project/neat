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

#include <neat-socketapi.h>
#include <identifierbitmap.h>

#include "neat-socketapi-internals.h"

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#if defined(HAVE_NETINET_SCTP_H)
#include <netinet/sctp.h>
#endif


/* ###### Map system socket into NEAT socket descriptor space ############ */
int nsa_map_socket(int systemSD, int neatSD)
{
   pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
   const int result = nsa_socket_internal(0, 0, 0, systemSD, NULL, neatSD);
   pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
   return(result);
}


/* ###### Unmap system socket from NEAT socket descriptor space ########## */
int nsa_unmap_socket(int neatSD)
{
   return(nsa_close(neatSD));
}


/* ###### Initialise ##################################################### */
int nsa_init()
{
   const bool success = (nsa_initialize() != NULL);
   return((success == true) ? 0 : -1);
}


/* ###### NEAT socket() implementation ################################### */
int nsa_socket(int domain, int type, int protocol, const char* properties)
{
   int result = -1;

   if(nsa_initialize() != NULL) {
      pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);

      if(properties != NULL) {
         struct neat_flow* flow = neat_new_flow(gSocketAPIInternals->nsi_neat_context);
         if(flow != NULL) {
            if(neat_set_property(gSocketAPIInternals->nsi_neat_context, flow, properties) == 0) {
               result = nsa_socket_internal(AF_UNSPEC, 0, 0, -1, flow, -1);
            }
            else {
               neat_close(gSocketAPIInternals->nsi_neat_context, flow);
               errno = EINVAL;
            }
         }
         else {
            errno = EINVAL;
         }
      }
      else {
         result = nsa_socket_internal(domain, type, protocol, -1, NULL, -1);
      }

      pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
   }
   else {
      errno = ENXIO;
   }
   return(result);
}


/* ###### NEAT close() implementation #################################### */
int nsa_close(int sockfd)
{
   pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
   struct neat_socket* neatSocket = nsa_get_socket_for_descriptor(sockfd);
   int                 result     = 0;
   if(neatSocket != NULL) {
      if(neatSocket->ns_flow != NULL) {
         pthread_mutex_lock(&neatSocket->ns_mutex);
         rbt_remove(&gSocketAPIInternals->nsi_socket_set, &neatSocket->ns_node);
         pthread_mutex_unlock(&neatSocket->ns_mutex);
         neat_close(gSocketAPIInternals->nsi_neat_context, neatSocket->ns_flow);

         /* Finally, finish the main loop's waiting, in order to let it
         * process the closing request. */
         nsa_notify_main_loop();
      }
      else {
         nsa_close_internal(neatSocket);
      }
   }
   else {
      errno  = EBADF;
      result = -1;
   }
   pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
   return(result);
}


/* ###### NEAT close() implementation #################################### */
int nsa_fcntl(int sockfd, int cmd, ...)
{
   GET_NEAT_SOCKET(sockfd)

   va_list va;
   unsigned long int arg;
   va_start (va, cmd);
   arg = va_arg (va, unsigned long int);
   va_end (va);

   if(cmd == F_GETFL) {
      int flags = 0;
      pthread_mutex_lock(&neatSocket->ns_mutex);
      if(neatSocket->ns_flags & NSAF_NONBLOCKING) {
         flags |= O_NONBLOCK;
      }
      pthread_mutex_unlock(&neatSocket->ns_mutex);
      return(flags);
   }
   else {
      pthread_mutex_lock(&neatSocket->ns_mutex);
      if(arg & O_NONBLOCK) {
         neatSocket->ns_flags |= NSAF_NONBLOCKING;
      }
      else {
         neatSocket->ns_flags &= ~NSAF_NONBLOCKING;
      }
      pthread_mutex_unlock(&neatSocket->ns_mutex);
      return(0);
   }

   errno = ENXIO;
   return(-1);
}


/* ###### Copy bind options ############################################## */
static int copy_options(struct neat_tlv** optionsPtr,
                        int*              optcntPtr,
                        struct neat_tlv*  newOptions,
                        const int         newOptCount)
{
   if(*optionsPtr) {
      free(*optionsPtr);
      *optionsPtr = NULL;
      *optcntPtr  = 0;
   }
   if(newOptions) {
      *optionsPtr = (struct neat_tlv*)malloc(newOptCount * sizeof(struct neat_tlv));
      if(*optionsPtr == NULL) {
         errno = ENOMEM;
         return(-1);
      }
      memcpy(*optionsPtr, newOptions, newOptCount * sizeof(struct neat_tlv));
      *optcntPtr = newOptCount;
   }
   return(0);
}


/* ###### NEAT bindn() implementation #################################### */
int nsa_bindn(int sockfd, uint16_t port, int flags,
              struct neat_tlv* opt, const int optcnt)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {
      if(copy_options(&neatSocket->ns_options, &neatSocket->ns_optcount,
                      opt, optcnt) < 0) {
         return(-1);
      }
      neatSocket->ns_port = port;
      return(0);
   }
   errno = ENOTSUP;
   return(-1);
}


/* ###### NEAT bindx() implementation #################################### */
int nsa_bindx(int sockfd, const struct sockaddr* addrs, int addrcnt, int flags,
              struct neat_tlv* opt, const int optcnt)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {
      if(addrcnt >= 1) {
         if(copy_options(&neatSocket->ns_options, &neatSocket->ns_optcount,
                         opt, optcnt) < 0) {
            return(-1);
         }
         neatSocket->ns_port = get_port(addrs);
         return(0);
      }
      else {
         errno = EINVAL;
         return(-1);
      }
   }
   else {
       if( (addrcnt == 1) && (flags == 0) ) {
          return(bind(neatSocket->ns_socket_sd, addrs, get_socklen(addrs)));
       }
       else {
#if defined(HAVE_NETINET_SCTP_H)
          return(sctp_bindx(neatSocket->ns_socket_sd, (struct sockaddr*)addrs, addrcnt, flags));
#else
          errno = EOPNOTSUPP;
          return(-1);
#endif
       }
   }
}


/* ###### NEAT bind() implementation ##################################### */
int nsa_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen,
             struct neat_tlv* opt, const int optcnt)
{
   return(nsa_bindx(sockfd, addr, 1, 0, opt, optcnt));
}


/* ###### NEAT connectn() implementation ################################# */
int nsa_connectn(int                 sockfd,
                 const char*         name,
                 const uint16_t      port,
                 neat_assoc_t*       id,
                 struct neat_tlv*    opt,
                 const int           optcnt)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {
      return(nsa_connectx_internal(neatSocket,
                                   name, port, id, opt, optcnt));
   }
   else {
      errno = ENOTSUP;
   }
   return(-1);
}


/* ###### NEAT connectx() implementation ################################# */
int nsa_connectx(int                    sockfd,
                 const struct sockaddr* addrs,
                 int                    addrcnt,
                 neat_assoc_t*          id,
                 struct neat_tlv*       opt,
                 const int              optcnt)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {
      if(addrcnt >= 1) {
         /* ====== Obtain address and port =============================== */
         char remoteHost[512];
         char remoteService[128];
         const int error = getnameinfo(&addrs[0], get_socklen(&addrs[0]),
                                       (char*)&remoteHost, sizeof(remoteHost),
                                       (char*)&remoteService, sizeof(remoteService),
                                       NI_NUMERICHOST|NI_NUMERICSERV);
         if(error != 0) {
            errno = EINVAL;
            return(-1);
         }

         /* ====== Connect =============================================== */
         return(nsa_connectx_internal(neatSocket,
                                      remoteHost, atoi(remoteService),
                                      id, opt, optcnt));
      }
      else {
         errno = EINVAL;
      }
      return(-1);
   }
   else {
       if( (addrcnt == 1) && (id == NULL) ) {
          return(connect(neatSocket->ns_socket_sd, addrs, get_socklen(addrs)));
       }
       else {
#if defined(HAVE_NETINET_SCTP_H)
          return(sctp_connectx(neatSocket->ns_socket_sd,
                               (struct sockaddr*)addrs, addrcnt, (sctp_assoc_t*)id));
#else
          errno = EOPNOTSUPP;
          return(-1);
#endif
       }
   }
}


/* ###### NEAT connect() implementation ################################## */
int nsa_connect(int                    sockfd,
                const struct sockaddr* addr,
                socklen_t              addrlen,
                struct neat_tlv*       opt,
                const int              optcnt)
{
   return(nsa_connectx(sockfd, addr, 1, NULL, opt, optcnt));
}


/* ###### NEAT listen() implementation ################################### */
int nsa_listen(int sockfd, int backlog)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {

      pthread_mutex_lock(&neatSocket->ns_mutex);
      neat_error_code result = NEAT_OK;
      if(!(neatSocket->ns_flags & NSAF_LISTENING)) {
         result = neat_accept(gSocketAPIInternals->nsi_neat_context,
                              neatSocket->ns_flow, neatSocket->ns_port,
                              neatSocket->ns_options, neatSocket->ns_optcount);
      }
      if(result == NEAT_OK) {
         neatSocket->ns_listen_backlog = backlog;
         if(backlog > 0) {
            neatSocket->ns_flags |= NSAF_LISTENING;
         }
         else {
            neatSocket->ns_flags &= ~NSAF_LISTENING;
         }
      }
      pthread_mutex_unlock(&neatSocket->ns_mutex);

      switch(result) {
         case NEAT_OK:
            return(0);
          break;
         case NEAT_ERROR_UNABLE:
             errno = EOPNOTSUPP;
             return(-1);
          break;
         case NEAT_ERROR_BAD_ARGUMENT:
             errno = EINVAL;
             return(-1);
          break;
         case NEAT_ERROR_OUT_OF_MEMORY:
             errno = ENOMEM;
             return(-1);
          break;
      }

      errno = ENOENT;   /* Unexpected error from NEAT Core */
      return(-1);
   }
   else {
      return(listen(neatSocket->ns_socket_sd, backlog));
   }
}


/* ###### NEAT accept() implementation ################################### */
int nsa_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {
      int result = -1;

      if( (addrlen == NULL) ||
          ((*addrlen == 0) || (*addrlen >= sizeof(struct sockaddr_in))) ) {

         pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
         pthread_mutex_lock(&neatSocket->ns_mutex);

         if(neatSocket->ns_flags & NSAF_LISTENING) {
            /* ====== Accept new socket ================================== */
            struct neat_socket* newSocket = TAILQ_FIRST(&neatSocket->ns_accept_list);
            while( (newSocket == NULL) &&
                   (!(neatSocket->ns_flags & NSAF_NONBLOCKING)) ) {
               /* ====== Blocking mode: wait ============================= */
               es_has_fired(&neatSocket->ns_read_signal);   /* Clear read signal */
               nsa_set_socket_event_on_read(neatSocket, true);

               pthread_mutex_unlock(&neatSocket->ns_mutex);
               pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
               nsa_wait_for_event(neatSocket, POLLIN, -1);
               pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);

               /* ====== Check whether the socket has been closed ======== */
               if(neatSocket != nsa_get_socket_for_descriptor(sockfd)) {
                  /* The socket has been closed -> return with EBADF. */
                  pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
                  errno = EBADF;
                  return(-1);
               }

               /* ====== Try again ======================================= */
               pthread_mutex_lock(&neatSocket->ns_mutex);
               newSocket = TAILQ_FIRST(&neatSocket->ns_accept_list);
            }

            /* ====== Remove new socket from accept queue ================ */
            if(newSocket) {
               TAILQ_REMOVE(&neatSocket->ns_accept_list, newSocket, ns_accept_node);
               newSocket->ns_acceptor = NULL;

               result = newSocket->ns_descriptor;

               /* ====== Fill in peer address ============================ */
               if(addrlen != NULL) {
                  if(nsa_getpeername(newSocket->ns_descriptor, addr, addrlen) < 0) {
                     *addrlen = 0;
                  }
               }
            }

            if(TAILQ_FIRST(&neatSocket->ns_accept_list) == NULL) {
               neatSocket->ns_flags &= ~NSAF_READABLE;
               es_has_fired(&neatSocket->ns_read_signal);   /* Clear read signal */
            }
        }
        else {
           errno  = EOPNOTSUPP;
        }

        pthread_mutex_unlock(&neatSocket->ns_mutex);
        pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);

      }
      else {
         errno = EINVAL;
      }

      return(result);
   }
   else {
      return(accept(neatSocket->ns_socket_sd, addr, addrlen));
   }
}


/* ###### NEAT shutdown() implementation ################################# */
int nsa_shutdown(int sockfd, int how)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {
      pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
      pthread_mutex_lock(&neatSocket->ns_mutex);
      const neat_error_code result =
         neat_shutdown(gSocketAPIInternals->nsi_neat_context,
                       neatSocket->ns_flow);
      pthread_mutex_unlock(&neatSocket->ns_mutex);
      pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);

      switch(result) {
         case NEAT_OK:
            return(0);
          break;
         case NEAT_ERROR_IO:
             errno = EIO;
             return(-1);
          break;
      }

      errno = ENOENT;   /* Unexpected error from NEAT Core */
      return(-1);
   }
   else {
      return(shutdown(neatSocket->ns_socket_sd, how));
   }
}


/* ###### NEAT peeloff() implementation ################################## */
int nsa_peeloff(int sockfd, neat_assoc_t id)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {

      return(0);
   }
   else {
#if defined(HAVE_NETINET_SCTP_H)
      return(sctp_peeloff(neatSocket->ns_socket_sd, id));
#else
      errno = EOPNOTSUPP;
      return(-1);
#endif
   }
}


/* ###### NEAT ioctl() implementation #################################### */
int nsa_getsockopt(int sockfd, int level,
                   int optname, void* optval, socklen_t* optlen)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {
      pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
      pthread_mutex_lock(&neatSocket->ns_mutex);

      int result = -1;
      if(level == SOL_SOCKET) {
         switch(optname) {
            case SO_RCVBUF:
               if(*optlen >= (socklen_t)sizeof(int)) {
                  *((int*)optval) = 1024*1024;
                  *optlen         = sizeof(int);
                  result = 0;
               }
               else {
                  errno = EINVAL;
               }
             break;
            case SO_SNDBUF:
               if(*optlen >= (socklen_t)sizeof(int)) {
                  *((int*)optval) = 1024*1024;
                  *optlen         = sizeof(int);
                  result = 0;
               }
               else {
                  errno = EINVAL;
               }
             break;
            default:
               errno = EOPNOTSUPP;
             break;
         }
      }
      else {
         errno = EOPNOTSUPP;
      }

      pthread_mutex_unlock(&neatSocket->ns_mutex);
      pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
      return(result);
   }
   else {
      return(getsockopt(neatSocket->ns_socket_sd, level, optname, optval, optlen));
   }
}


/* ###### NEAT ioctl() implementation #################################### */
int nsa_setsockopt(int sockfd, int level,
                   int optname, const void* optval, socklen_t optlen)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {
      pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
      pthread_mutex_lock(&neatSocket->ns_mutex);

      int result = -1;
      if(level == SOL_SOCKET) {
         switch(optname) {
            case SO_RCVBUF:
               if(optlen >= (socklen_t)sizeof(int)) {
//                ... = *((int*)optval);
                  result = 0;
               }
               else {
                  errno = EINVAL;
               }
             break;
            case SO_SNDBUF:
               if(optlen >= (socklen_t)sizeof(int)) {
//                ... = *((int*)optval);
                  result = 0;
               }
               else {
                  errno = EINVAL;
               }
             break;
            default:
               errno = EOPNOTSUPP;
             break;
         }
      }
      else {
         errno = EOPNOTSUPP;
      }

      pthread_mutex_unlock(&neatSocket->ns_mutex);
      pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
      return(result);
   }
   else {
      return(setsockopt(neatSocket->ns_socket_sd, level, optname, optval, optlen));
   }
}


/* ###### NEAT opt_info() implementation ################################# */
int nsa_opt_info(int sockfd, neat_assoc_t id, int opt, void* arg, socklen_t* size)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
#if defined(HAVE_NETINET_SCTP_H)
      return(sctp_opt_info(neatSocket->ns_socket_sd, id, opt, arg, size));
#else
      errno = EOPNOTSUPP;
      return(-1);
#endif
   }
}


/* ###### NEAT set_secure_identity() implementation ###################### */
int nsa_set_secure_identity(int sockfd, const char* pem)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {
      pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
      pthread_mutex_lock(&neatSocket->ns_mutex);
/*      const neat_error_code result = */
         neat_secure_identity(gSocketAPIInternals->nsi_neat_context,
                              neatSocket->ns_flow,
                              pem, NEAT_CERT_NONE);
      pthread_mutex_unlock(&neatSocket->ns_mutex);
      pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);

      // Security in the NEAT Core API is currently broken!
      // It will not work here as well ...
      assert(false);
/*
      switch(result) {
         case NEAT_OK:
            return(0);
          break;
      }
*/
      errno = ENOENT;   /* Unexpected error from NEAT Core */
      return(-1);
   }
   errno = EOPNOTSUPP;
   return(-1);
}


/* ###### NEAT nsa_getladdrs()/nsa_getpaddrs() implementation ############ */
static int nsa_getlpaddrs(int sockfd, neat_assoc_t id, struct sockaddr** addrs, const bool local)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {
      pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
      pthread_mutex_lock(&neatSocket->ns_mutex);
      const int result = neat_getlpaddrs(gSocketAPIInternals->nsi_neat_context,
                                         neatSocket->ns_flow,
                                         addrs, local);
      pthread_mutex_unlock(&neatSocket->ns_mutex);
      pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
      return(result);
   }
   else {
#if defined(HAVE_NETINET_SCTP_H)
      return((local) ? sctp_getladdrs(sockfd, id, addrs) :
                       sctp_getpaddrs(sockfd, id, addrs));
#else
      errno = EOPNOTSUPP;
      return(-1);
#endif
   }
}


/* ###### NEAT nsa_getladdrs() implementation ############################ */
int nsa_getladdrs(int sockfd, neat_assoc_t id, struct sockaddr** addrs)
{
   return(nsa_getlpaddrs(sockfd, id, addrs, 1));
}


/* ###### NEAT nsa_freeladdrs() implementation ########################### */
void nsa_freeladdrs(struct sockaddr* addrs)
{
   neat_freelpaddrs(addrs);
}


/* ###### NEAT nsa_getpaddrs() implementation ############################ */
int nsa_getpaddrs(int sockfd, neat_assoc_t id, struct sockaddr** addrs)
{
   return(nsa_getlpaddrs(sockfd, id, addrs, 0));
}


/* ###### NEAT nsa_freepaddrs() implementation ########################### */
void nsa_freepaddrs(struct sockaddr* addrs)
{
   neat_freelpaddrs(addrs);
}


/* ###### NEAT nsa_getsockname()/nsa_getpeername() implementation ######## */
static int nsa_getlpname(int sockfd, struct sockaddr* name, socklen_t* namelen, const bool local)
{
   if(*namelen >= sizeof(struct sockaddr_in)) {
      struct sockaddr* addrs = NULL;
      if(nsa_getlpaddrs(sockfd, 0, &addrs, local) > 0) {
         *namelen = MIN(*namelen, get_socklen(addrs));
         memcpy(name, addrs, *namelen);
         free(addrs);
         return(0);
      }
      else {
         errno = EBADF;
      }
   }
   else {
      errno = EINVAL;
   }
   return(-1);
}


/* ###### NEAT nsa_getsockname() implementation ########################## */
int nsa_getsockname(int sockfd, struct sockaddr* name, socklen_t* namelen)
{
   return(nsa_getlpname(sockfd, name, namelen, 1));
}


/* ###### NEAT nsa_getpeername() implementation ########################## */
int nsa_getpeername(int sockfd, struct sockaddr* name, socklen_t* namelen)
{
   return(nsa_getlpname(sockfd, name, namelen, 0));
}


/* ###### NEAT open() implementation ##################################### */
int nsa_open(const char* pathname, int flags, mode_t mode)
{
   const int fd = open(pathname, flags, mode);
   if(fd >= 0) {
      pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);

      int       result;
      const int newFD = nsa_socket_internal(0, 0, 0, fd, NULL, -1);
      if(newFD >= 0) {
         result = newFD;
      }
      else {
         errno = ENOMEM;
         close(fd);
         result = -1;
      }

      pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
      return(result);
   }
   return(-1);
}


/* ###### NEAT creat() implementation #################################### */
int nsa_creat(const char* pathname, mode_t mode)
{
   const int fd = creat(pathname, mode);
   if(fd >= 0) {
      pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);

      int       result;
      const int newFD = nsa_socket_internal(0, 0, 0, fd, NULL, -1);
      if(newFD >= 0) {
         result = newFD;
      }
      else {
         errno = ENOMEM;
         close(fd);
         result = -1;
      }

      pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
      return(result);
   }
   return(-1);
}


/* ###### NEAT ioctl() implementation #################################### */
int nsa_ioctl(int fd, int request, const void* argp)
{
   GET_NEAT_SOCKET(fd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      return(ioctl(neatSocket->ns_socket_sd, fd, request, argp));
   }
}


/* ###### NEAT pipe() implementation ##################################### */
int nsa_pipe(int fds[2])
{
   int sysFDs[2];
   if(pipe((int*)&sysFDs) == 0) {
      pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
      fds[0] = nsa_socket_internal(0, 0, 0, sysFDs[0], NULL, -1);
      if(fds[0] >= 0) {
         fds[1] = nsa_socket_internal(0, 0, 0, sysFDs[1], NULL, -1);
         if(fds[1] >= 0) {
            pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
            return(0);
         }
         nsa_close(fds[0]);
         fds[0] = -1;
      }
      errno = ENOMEM;
      close(sysFDs[0]);
      close(sysFDs[1]);
      pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
   }
   return(-1);
}
