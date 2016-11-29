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
#include <math.h>


/* ###### NEAT poll() implementation ##################################### */
int nsa_poll(struct pollfd* fdlist, long unsigned int count, int time)
{
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
   waitingTime = (1000 * timeout->tv_sec) + (int)ceil((double)timeout->tv_usec / 1000.0);
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
