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
      pthread_mutex_lock(&gSocketAPIInternals->socket_set_mutex);

      if(properties != NULL) {
         struct neat_flow* flow = neat_new_flow(gSocketAPIInternals->neat_context);
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

      pthread_mutex_unlock(&gSocketAPIInternals->socket_set_mutex);
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

   pthread_mutex_lock(&neatSocket->mutex);

   /* ====== Close socket ================================================ */
   if(neatSocket->flow != NULL) {
      neat_close(gSocketAPIInternals->neat_context, neatSocket->flow);
      neatSocket->flow = NULL;
   }
   else if(neatSocket->socket_sd >= 0) {
      if(neatSocket->flags & NSAF_CLOSE_ON_REMOVAL) {
         close(neatSocket->socket_sd);
      }
      neatSocket->socket_sd = -1;
   }

   /* ====== Remove socket ===============================================*/
   pthread_mutex_lock(&gSocketAPIInternals->socket_set_mutex);
   rbt_remove(&gSocketAPIInternals->socket_set, &neatSocket->node);
   pthread_mutex_unlock(&gSocketAPIInternals->socket_set_mutex);

   pthread_mutex_unlock(&neatSocket->mutex);
   pthread_mutex_destroy(&neatSocket->mutex);
   free(neatSocket);
   return(0);
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
      pthread_mutex_lock(&neatSocket->mutex);
      if(neatSocket->flags & NSAF_NONBLOCKING) {
         flags |= O_NONBLOCK;
      }
      pthread_mutex_unlock(&neatSocket->mutex);
      return(flags);
   }
   else {
       pthread_mutex_lock(&neatSocket->mutex);
      if(arg & O_NONBLOCK) {
         neatSocket->flags |= NSAF_NONBLOCKING;
      }
      else {
         neatSocket->flags &= ~NSAF_NONBLOCKING;
      }
      pthread_mutex_unlock(&neatSocket->mutex);
      return(0);
   }

   errno = ENXIO;
   return(-1);
}


/* ###### NEAT bind() implementation ##################################### */
int nsa_bind(int sockfd, struct sockaddr* my_addr, socklen_t addrlen)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->flow != NULL) {

      return(0);
   }
   else {
      return(bind(neatSocket->socket_sd, my_addr, addrlen));
   }
}


/* ###### NEAT connect() implementation ################################## */
int nsa_connect(int sockfd, const struct sockaddr* serv_addr, socklen_t addrlen)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->flow != NULL) {

      return(0);
   }
   else {
      return(connect(neatSocket->socket_sd, serv_addr, addrlen));
   }
}


/* ###### NEAT listen() implementation ################################### */
int nsa_listen(int sockfd, int backlog)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->flow != NULL) {

      return(0);
   }
   else {
      return(listen(neatSocket->socket_sd, backlog));
   }
}


/* ###### NEAT accept() implementation ################################### */
int nsa_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->flow != NULL) {

      return(0);
   }
   else {
      return(accept(neatSocket->socket_sd, addr, addrlen));
   }
}


/* ###### NEAT shutdown() implementation ################################# */
int nsa_shutdown(int sockfd, int how)
{
   GET_NEAT_SOCKET(sockfd)
   if(neatSocket->flow != NULL) {

      return(0);
   }
   else {
      return(shutdown(neatSocket->socket_sd, how));
   }
}


/*
static bool isInitialized = false;

int nsa_socket(int domain, int type, int protocol);
int nsa_open(const char* pathname, int flags, mode_t mode);
int nsa_creat(const char* pathname, mode_t mode);
int nsa_bind(int sockfd, struct sockaddr* my_addr, socklen_t addrlen);
int nsa_connect(int sockfd, const struct sockaddr* serv_addr, socklen_t addrlen);
int nsa_listen(int s, int backlog);
int nsa_accept(int s,  struct  sockaddr * addr,  socklen_t* addrlen);
int nsa_shutdown(int s, int how);
int nsa_close(int fd);
*/
