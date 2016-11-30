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

      if(properties != NULL) {
         pthread_mutex_lock(&gSocketAPIInternals->socket_set_mutex);
         struct neat_flow* flow = neat_new_flow(gSocketAPIInternals->neat_context);
         if(flow != NULL) {
            result = nsa_socket_internal(AF_UNSPEC, 0, 0, -1, flow, -1);
         }
         else {
            errno = EINVAL;
         }
         pthread_mutex_unlock(&gSocketAPIInternals->socket_set_mutex);
      }
      else {
         result = nsa_socket_internal(domain, type, protocol, -1, NULL, -1);
      }

   }
   else {
      errno = EUNATCH;
   }
   return(result);
}


/* ###### NEAT close() implementation #################################### */
int nsa_close(int fd)
{
   struct neat_socket* neatSocket = nsa_get_socket_for_descriptor(fd);
   if(neatSocket != NULL) {
      if(neatSocket->flow != NULL) {
         pthread_mutex_lock(&gSocketAPIInternals->socket_set_mutex);
         neat_close(gSocketAPIInternals->neat_context, neatSocket->flow);
         neatSocket->flow = NULL;
         pthread_mutex_unlock(&gSocketAPIInternals->socket_set_mutex);
      }
      else if(neatSocket->socket_sd >= 0) {
         if(neatSocket->flags & NSAF_CLOSE_ON_REMOVAL) {
            printf("close(%d)\n", neatSocket->socket_sd);;
            close(neatSocket->socket_sd);
            neatSocket->socket_sd = -1;
         }
         else   printf("not close(%d)\n", neatSocket->socket_sd);;
      }
      pthread_mutex_destroy(&neatSocket->mutex);
      free(neatSocket);
      return(0);
   }
   errno = EBADF;
   return(-1);
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
