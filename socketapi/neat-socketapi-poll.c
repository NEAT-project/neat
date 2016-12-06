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

#include "neat-socketapi-internals.h"

#include <stddef.h>
#include <stdlib.h>
#include <errno.h>


/* ###### NEAT poll() implementation ##################################### */
int nsa_poll(struct pollfd* fdlist, long unsigned int count, int time)
{
#if 0
   struct neat_socket* neat_socket;
   int                    fdbackup[FD_SETSIZE];
   int                    result;
   unsigned int           i;

   /* ====== Check for problems ========================================== */
   if(nfds > FD_SETSIZE) {
      errno = EINVAL;
      return(-1);
   }

   /* ====== Collect data for poll() call ================================ */
   result = 0;
   for(i = 0;i < nfds;i++) {
      fdbackup[i] = ufds[i].fd;
      struct neat_socket* neatSocket = nsa_get_socket_for_descriptor(ufds[i].fd);
      if(neatSocket != NULL) {
         pthread_mutex_lock(&neatSocket->nsa_mutex);
         ufds[i].fd      = neatSocket->ns_
         ufds[i].revents = 0;
         if((ufds[i].events & POLLIN) && (nq_has_data(&neat_socket->ns_notifications))) {
            result++;
            ufds[i].revents = POLLIN;
         }
         pthread_mutex_unlock(&neatSocket->nsa_mutex);
      }
      else {
         ufds[i].fd = -1;
      }
   }

   /* ====== Do poll() =================================================== */
   if(result == 0) {
      /* Only call poll() when there are no notifications */
      result = ext_poll(ufds, nfds, timeout);
   }

   /* ====== Handle results ============================================== */
   for(i = 0;i < nfds;i++) {
      neat_socket = getRSerPoolSocketForDescriptor(fdbackup[i]);
      if((neat_socket != NULL) && (neat_socket->SessionAllocationBitmap != NULL)) {
         threadSafetyLock(&neat_socket->Mutex);

         /* ======= Check for control channel data ======================= */
         if(ufds[i].revents & POLLIN) {
            LOG_VERBOSE4
            fprintf(stdlog, "RSerPool socket %d (socket %d) has <read> flag set -> Check, if it has to be handled by rsplib...\n",
                     neat_socket->Descriptor, neat_socket->Socket);
            LOG_END
            if(handleControlChannelAndNotifications(neat_socket)) {
               LOG_VERBOSE4
               fprintf(stdlog, "RSerPool socket %d (socket %d) had <read> event for rsplib only. Clearing <read> flag\n",
                        neat_socket->Descriptor, neat_socket->Socket);
               LOG_END
               ufds[i].revents &= ~POLLIN;
            }
         }

         /* ====== Set <read> flag for RSerPool notifications? =========== */
         if((ufds[i].events & POLLIN) &&
            (notificationQueueHasData(&neat_socket->Notifications))) {
            ufds[i].revents |= POLLIN;
         }

         threadSafetyUnlock(&neat_socket->Mutex);
      }
      ufds[i].fd = fdbackup[i];
   }

   return(result);
#endif
   return -1;
}


/* ###### NEAT select() implementation ################################### */
int nsa_select(int             n,
               fd_set*         readfds,
               fd_set*         writefds,
               fd_set*         exceptfds,
               struct timeval* timeout)
{
   struct pollfd ufds[FD_SETSIZE];
   int           nfds;
   int           waitingTime;
   int           result;
   int           i;

   /* ====== Check for problems ========================================== */
   if(n > (int)FD_SETSIZE) {
      errno = EINVAL;
      return(-1);
   }

   /* ====== Prepare pollfd array ======================================== */
   nfds = 0;
   for(i = 0;i < n;i++) {
      ufds[nfds].events = 0;
      if((readfds) && (FD_ISSET(i, readfds))) {
         ufds[nfds].fd = i;
         ufds[nfds].events |= POLLIN;
      }
      if((writefds) && (FD_ISSET(i, writefds))) {
         ufds[nfds].fd = i;
         ufds[nfds].events |= POLLOUT;
      }
      if((exceptfds) && (FD_ISSET(i, exceptfds))) {
         ufds[nfds].fd = i;
         ufds[nfds].events |= ~(POLLIN|POLLOUT);
      }
      if(ufds[nfds].events) {
         nfds++;
      }
   }

   /* ====== Call poll() and propagate results to fdsets ================= */
   waitingTime = (1000 * timeout->tv_sec) + (int)((timeout->tv_usec + 999) / 1000);
   result = nsa_poll((struct pollfd*)&ufds, nfds, waitingTime);
   if(result > 0) {
      for(i = 0;i < nfds;i++) {
         if( (!(ufds[i].events & POLLIN)) && (readfds) ) {
            FD_CLR(ufds[i].fd, readfds);
         }
         if( (!(ufds[i].events & POLLOUT)) && (writefds) ) {
            FD_CLR(ufds[i].fd, writefds);
         }
         if( (!(ufds[i].events & (POLLIN|POLLHUP|POLLNVAL))) && (exceptfds) ) {
            FD_CLR(ufds[i].fd, exceptfds);
         }
      }
   }

   return(result);
}
