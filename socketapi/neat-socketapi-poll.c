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


// Internal structure for nsa_poll().
struct poll_storage
{
   struct event_signal ps_global_signal;
   struct event_signal ps_read_signal;
   struct event_signal ps_write_signal;
   struct event_signal ps_exception_signal;
};


/* ###### NEAT poll() implementation ##################################### */
int nsa_poll(struct pollfd* ufds, const nfds_t nfds, int timeout)
{
   struct poll_storage pollStorage;
   int                 result;

   /* ====== Collect data for poll() call ================================ */
   pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);

   es_new(&pollStorage.ps_global_signal, NULL);
   es_new(&pollStorage.ps_read_signal,   &pollStorage.ps_global_signal);
   es_new(&pollStorage.ps_write_signal , &pollStorage.ps_global_signal);
   es_new(&pollStorage.ps_exception_signal, &pollStorage.ps_global_signal);

   result = 0;
   for(nfds_t i = 0;i < nfds;i++) {
      struct neat_socket* neatSocket = nsa_get_socket_for_descriptor(ufds[i].fd);
      if(neatSocket != NULL) {
         pthread_mutex_lock(&neatSocket->ns_mutex);
         if(neatSocket->ns_flow != NULL) {
            es_add_parent(&neatSocket->ns_read_signal, &pollStorage.ps_read_signal);
            es_add_parent(&neatSocket->ns_write_signal, &pollStorage.ps_write_signal);
            es_add_parent(&neatSocket->ns_exception_signal, &pollStorage.ps_exception_signal);
         }
         else {
            puts("FIXME! System sockets not handled yet!");
            abort();
         }
         pthread_mutex_unlock(&neatSocket->ns_mutex);
      }
      else {
         result = -1;
         errno  = EBADF;
      }
      ufds[i].revents = 0;
   }

   pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);


   /* ====== Wait for signal or timeout ================================== */
   if(result == 0) {
      /* Only wait when there are no notifications */
      es_timed_wait(&pollStorage.ps_global_signal, timeout);
   }


   /* ====== Handle results ============================================== */
   pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);

   for(nfds_t i = 0;i < nfds;i++) {
      struct neat_socket* neatSocket = nsa_get_socket_for_descriptor(ufds[i].fd);
      if(neatSocket != NULL) {
         pthread_mutex_lock(&neatSocket->ns_mutex);
         if(neatSocket->ns_flow != NULL) {
             if(ufds[i].events & POLLIN) {
                /* There is something to read (data, notification or error) */
                if( (neatSocket->ns_flags & (NSAF_READABLE|NSAF_BAD)) ||
                    (nq_has_data(&neatSocket->ns_notifications)) ) {
                   ufds[i].revents |= POLLIN;
                }
             }
             if(ufds[i].events & POLLOUT) {
                /* It is possible to write data */
                if(neatSocket->ns_flags & NSAF_WRITABLE) {
                   ufds[i].revents |= POLLOUT;
                }
             }
             if(neatSocket->ns_flags & NSAF_BAD) {
                /* There is an error */
                ufds[i].revents |= POLLERR;
             }
         }
         else {
            puts("FIXME! System sockets not handled yet!");
            abort();
         }
         pthread_mutex_unlock(&neatSocket->ns_mutex);
      }
      else {
         ufds[i].revents |= POLLNVAL;
      }
   }

   pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);

   return(result);
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
