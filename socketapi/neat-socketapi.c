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
#include <errno.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <netinet/sctp.h>


/* ###### Map system socket into NEAT socket descriptor space ############ */
int nsa_map_socket(int systemSD, int neatSD)
{
   return(nsa_socket_internal(0, 0, 0, systemSD, NULL, neatSD));
}


/* ###### Unmap system socket from NEAT socket descriptor space ########## */
int nsa_unmap_socket(int neatSD)
{
   return(nsa_close(neatSD));
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
            result = nsa_socket_internal(AF_UNSPEC, 0, 0, -1, flow, -1);
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
      errno = EUNATCH;
   }
   return(result);
}


/* ###### NEAT close() implementation #################################### */
int nsa_close(int fd)
{
   GET_NEAT_SOCKET(fd)

   pthread_mutex_lock(&neatSocket->ns_mutex);

   /* ====== Close socket ================================================ */
   if(neatSocket->ns_flow != NULL) {
      neat_close(gSocketAPIInternals->nsi_neat_context, neatSocket->ns_flow);
      neatSocket->ns_flow = NULL;
   }
   else if(neatSocket->ns_socket_sd >= 0) {
      if(neatSocket->ns_flags & NSAF_CLOSE_ON_REMOVAL) {
         close(neatSocket->ns_socket_sd);
      }
      neatSocket->ns_socket_sd = -1;
   }

   /* ====== Remove socket ===============================================*/
   pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
   rbt_remove(&gSocketAPIInternals->nsi_socket_set, &neatSocket->ns_node);
   ibm_free_id(gSocketAPIInternals->nsi_socket_identifier_bitmap, neatSocket->ns_descriptor);
   neatSocket->ns_descriptor = -1;
   pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);

   nq_delete(&neatSocket->ns_notifications);
   es_delete(&neatSocket->ns_exception_signal);
   es_delete(&neatSocket->ns_write_signal);
   es_delete(&neatSocket->ns_read_signal);
   pthread_mutex_unlock(&neatSocket->ns_mutex);
   pthread_mutex_destroy(&neatSocket->ns_mutex);
   free(neatSocket);
   return(0);
}


/* ###### NEAT bindx() implementation #################################### */
int nsa_bindx(int sockfd, const struct sockaddr* addrs, int addrcnt, int flags)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {

      return(0);
   }
   else {
       if( (addrcnt == 1) && (flags == 0) ) {
          return(bind(neatSocket->ns_socket_sd, addrs, get_socklen(addrs)));
       }
       else {
          abort();   // FIXME!
//           return(sctp_bindx(neatSocket->ns_socket_sd, (struct sockaddr*)addrs, addrcnt, flags));
       }
   }
}


/* ###### NEAT bind() implementation ##################################### */
int nsa_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
   return(nsa_bindx(sockfd, addr, 1, 0));
}


/* ###### NEAT connectx() implementation ################################# */
int nsa_connectx(int sockfd, const struct sockaddr* addrs, int addrcnt, neat_assoc_t* id)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {

      return(0);
   }
   else {
       if( (addrcnt == 1) && (id == NULL) ) {
          return(connect(neatSocket->ns_socket_sd, addrs, get_socklen(addrs)));
       }
       else {
          abort();   // FIXME!
//           return(sctp_connectx(neatSocket->ns_socket_sd, addrs, addrcnt, id));
       }
   }
}


/* ###### NEAT connect() implementation ################################## */
int nsa_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
   return(nsa_connectx(sockfd, addr, 1, NULL));
}


/* ###### NEAT listen() implementation ################################### */
int nsa_listen(int sockfd, int backlog)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {

      return(0);
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

      return(0);
   }
   else {
      return(accept(neatSocket->ns_socket_sd, addr, addrlen));
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
      abort();   // FIXME!
//      return(sctp_peeloff(neatSocket->ns_socket_sd, id));
   }
}


/* ###### NEAT shutdown() implementation ################################# */
int nsa_shutdown(int sockfd, int how)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->ns_flow != NULL) {

      return(0);
   }
   else {
      return(shutdown(neatSocket->ns_socket_sd, how));
   }
}


/* ###### NEAT close() implementation #################################### */
int nsa_fcntl(int fd, int cmd, ...)
{
   GET_NEAT_SOCKET(fd)

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


/* ###### NEAT shutdown() implementation ################################# */
int nsa_ioctl(int fd, int request, const void* argp)
{
   GET_NEAT_SOCKET(fd)
   if(neatSocket->ns_flow != NULL) {
      errno = ENOTSUP;
      return(0);
   }
   else {
      return(ioctl(neatSocket->ns_socket_sd, fd, request, argp));
   }
}


/* ###### NEAT open() implementation ##################################### */
int nsa_open(const char* pathname, int flags, mode_t mode)
{
   int fd = open(pathname, flags, mode);
   if(fd >= 0) {
      int newFD = nsa_socket_internal(0, 0, 0, fd, NULL, 0);
      if(newFD >= 0) {
         return(newFD);
      }
      errno = ENOMEM;
      close(fd);
   }
   return(-1);
}


/* ###### NEAT creat() implementation #################################### */
int nsa_creat(const char* pathname, mode_t mode)
{
   int fd = creat(pathname, mode);
   if(fd >= 0) {
      int newFD = nsa_socket_internal(0, 0, 0, fd, NULL, 0);
      if(newFD >= 0) {
         return(newFD);
      }
      errno = ENOMEM;
      close(fd);
   }
   return(-1);
}


/* ###### NEAT pipe() implementation ##################################### */
int nsa_pipe(int fds[2])
{
   int sysFDs[2];
   if(pipe((int*)&sysFDs) == 0) {
      fds[0] = nsa_socket_internal(0, 0, 0, sysFDs[0], NULL, 0);
      if(fds[0] >= 0) {
         fds[1] = nsa_socket_internal(0, 0, 0, sysFDs[1], NULL, 0);
         if(fds[1] >= 0) {
            return(0);
         }
         nsa_close(fds[0]);
         fds[0] = -1;
      }
      errno = ENOMEM;
      close(sysFDs[0]);
      close(sysFDs[1]);
   }
   return(-1);
}
