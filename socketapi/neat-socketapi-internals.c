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
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>


struct neat_socketapi_internals* gSocketAPIInternals = NULL;


static void* nsa_main_loop(void* args);



/* ###### Initialize recursive mutex ##################################### */
static void init_mutex(pthread_mutex_t* mutex)
{
   pthread_mutexattr_t attributes;
   pthread_mutexattr_init(&attributes);
   pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE);
   pthread_mutex_init(mutex, &attributes);
   pthread_mutexattr_destroy(&attributes);
}


/* ###### Set blocking mode ############################################## */
static bool set_non_blocking(int fd)
{
   int flags = fcntl(fd, F_GETFL, 0);
   if(flags != -1) {
      flags |= O_NONBLOCK;
      if(fcntl(fd, F_SETFL, flags) == 0) {
         return(true);
      }
   }
   return(false);
}


/* ###### Initialize ##################################################### */
struct neat_socketapi_internals* nsa_initialize()
{
   if(gSocketAPIInternals != NULL) {
      return(gSocketAPIInternals);
   }

   gSocketAPIInternals = calloc(1, sizeof(struct neat_socketapi_internals));
   if(gSocketAPIInternals != NULL) {

      /* ====== Initialize socket storage ============================= */
      gSocketAPIInternals->main_loop_pipe[0] = -1;
      gSocketAPIInternals->main_loop_pipe[1] = -1;
      init_mutex(&gSocketAPIInternals->socket_set_mutex);
      rbt_new(&gSocketAPIInternals->socket_set,
              nsa_socket_print_function,
              nsa_socket_comparison_function);

      /* ====== Initialize identifier bitmap ============================= */
      gSocketAPIInternals->socket_identifier_bitmap = ibm_new(FD_SETSIZE);
      if(gSocketAPIInternals->socket_identifier_bitmap != NULL) {
         /* ====== Map stdin, stdout, stderr file descriptors ============ */
         assert(nsa_map_socket(STDOUT_FILENO, STDOUT_FILENO) == STDOUT_FILENO);
         assert(nsa_map_socket(STDIN_FILENO,  STDIN_FILENO)  == STDIN_FILENO);
         assert(nsa_map_socket(STDERR_FILENO, STDERR_FILENO) == STDERR_FILENO);

         /* ====== NEAT context ========================================== */
         gSocketAPIInternals->neat_context = neat_init_ctx();
         if(gSocketAPIInternals->neat_context != NULL) {

            /* ====== Initialize main loop =============================== */
            if(pipe((int*)&gSocketAPIInternals->main_loop_pipe) >= 0) {
               set_non_blocking(gSocketAPIInternals->main_loop_pipe[0]);
               set_non_blocking(gSocketAPIInternals->main_loop_pipe[1]);

               pthread_mutex_lock(&gSocketAPIInternals->socket_set_mutex);
               gSocketAPIInternals->main_loop_thread_shutdown = false;
               pthread_mutex_unlock(&gSocketAPIInternals->socket_set_mutex);

               if(pthread_create(&gSocketAPIInternals->main_loop_thread, NULL, &nsa_main_loop, gSocketAPIInternals) == 0) {
                  return(gSocketAPIInternals);
               }
            }
         }
      }
   }

   /* Something went wrong! */
   fputs("Failed to initialize NEAT structures!\n", stderr);
   nsa_cleanup();

   return(NULL);
}


/* ###### Initialize ##################################################### */
struct neat_socketapi_internals* nsa_get()
{
   return(gSocketAPIInternals);
}


/* ###### Clean up ####################################################### */
void nsa_cleanup()
{
   if(gSocketAPIInternals) {
      if(gSocketAPIInternals->main_loop_thread != 0) {
         pthread_mutex_lock(&gSocketAPIInternals->socket_set_mutex);
         gSocketAPIInternals->main_loop_thread_shutdown = true;
         pthread_mutex_unlock(&gSocketAPIInternals->socket_set_mutex);
         nsa_notify_main_loop();
         assert(pthread_join(gSocketAPIInternals->main_loop_thread, NULL) == 0);
         gSocketAPIInternals->main_loop_thread = 0;
      }
      if(gSocketAPIInternals->main_loop_pipe[0] >= 0) {
         close(gSocketAPIInternals->main_loop_pipe[0]);
         gSocketAPIInternals->main_loop_pipe[0] = -1;
      }
      if(gSocketAPIInternals->main_loop_pipe[1] >= 0) {
         close(gSocketAPIInternals->main_loop_pipe[1]);
         gSocketAPIInternals->main_loop_pipe[1] = -1;
      }
      if(gSocketAPIInternals->neat_context) {
         neat_free_ctx(gSocketAPIInternals->neat_context);
         gSocketAPIInternals->neat_context = NULL;
      }
      if(gSocketAPIInternals->socket_identifier_bitmap)  {
         ibm_delete(gSocketAPIInternals->socket_identifier_bitmap);
         gSocketAPIInternals->socket_identifier_bitmap = NULL;
      }
      rbt_delete(&gSocketAPIInternals->socket_set);
      pthread_mutex_destroy(&gSocketAPIInternals->socket_set_mutex);
      free(gSocketAPIInternals);
      gSocketAPIInternals = NULL;
   }
}


/* ###### NEAT socket() implementation internals ######################### */
int nsa_socket_internal(int domain, int type, int protocol,
                        int customFD, struct neat_flow* flow, int requestedSD)
{
   struct neat_socket* neatSocket;

   /* ====== Handle different internal types ============================= */
   neatSocket = (struct neat_socket*)calloc(1, sizeof(struct neat_socket));
   if(neatSocket == NULL) {
      errno = ENOMEM;
      return(-1);
   }

   if(flow == NULL) {   /* NEAT flow */
      neatSocket->socket_sd = -1;
//       neatSocket->flow = ...
   }
   else if(customFD < 0) {   /* System socket to be created */
      neatSocket->socket_sd = socket(domain, type, protocol);
      neatSocket->flags     = NSAF_CLOSE_ON_REMOVAL;
   }
   else {   /* Existing socket, given by its socket descriptor */
      neatSocket->socket_sd = customFD;
   }

   /* ====== Set socket into non-blocking mode =========================== */
   if(neatSocket->socket_sd >= 0) {
      set_non_blocking(neatSocket->socket_sd);
   }

   /* ====== Initialize NEAT socket ====================================== */
   rbt_node_new(&neatSocket->node);
   init_mutex(&neatSocket->mutex);
   neatSocket->descriptor      = -1;   /* to be allocated below */
   neatSocket->socket_domain   = domain;
   neatSocket->socket_type     = type;
   neatSocket->socket_protocol = protocol;

   /* ====== Add new socket to socket storage ============================ */
   pthread_mutex_lock(&gSocketAPIInternals->socket_set_mutex);
   if(requestedSD < 0) {
      neatSocket->descriptor = ibm_allocate_id(gSocketAPIInternals->socket_identifier_bitmap);
   }
   else {
      neatSocket->descriptor = ibm_allocate_specific_id(gSocketAPIInternals->socket_identifier_bitmap,
                                                        requestedSD);
   }
   if(neatSocket->descriptor >= 0) {
      assert(rbt_insert(&gSocketAPIInternals->socket_set, &neatSocket->node) == &neatSocket->node);
   }
   pthread_mutex_unlock(&gSocketAPIInternals->socket_set_mutex);

   /* ====== Has there been a problem? =================================== */
   if(neatSocket->descriptor < 0) {
      if(neatSocket->flags & NSAF_CLOSE_ON_REMOVAL) {
         close(neatSocket->socket_sd);
      }
      pthread_mutex_destroy(&neatSocket->mutex);
      free(neatSocket);
      errno = EMFILE;
      return(-1);
   }
   return(neatSocket->descriptor);
}


/* ###### Print socket ################################################### */
void nsa_socket_print_function(const void* node, FILE* fd)
{
   const struct neat_socket* rserpoolSocket = (const struct neat_socket*)node;
   fprintf(fd, "%d ", rserpoolSocket->descriptor);
}


/* ###### Compare sockets ################################################ */
int nsa_socket_comparison_function(const void* node1, const void* node2)
{
   const struct neat_socket* rserpoolSocket1 = (const struct neat_socket*)node1;
   const struct neat_socket* rserpoolSocket2 = (const struct neat_socket*)node2;

   if(rserpoolSocket1->descriptor < rserpoolSocket2->descriptor) {
      return(-1);
   }
   else if(rserpoolSocket1->descriptor > rserpoolSocket2->descriptor) {
      return(1);
   }
   return(0);
}


/* ###### Find socket #################################################### */
struct neat_socket* nsa_get_socket_for_descriptor(int sd)
{
   struct neat_socket* rserpoolSocket;
   struct neat_socket  cmpSocket;

   cmpSocket.descriptor = sd;
   pthread_mutex_lock(&gSocketAPIInternals->socket_set_mutex);
   rserpoolSocket = (struct neat_socket*)rbt_find(&gSocketAPIInternals->socket_set,
                                                  &cmpSocket.node);
   pthread_mutex_unlock(&gSocketAPIInternals->socket_set_mutex);
   if(rserpoolSocket == NULL) {
      fprintf(stderr, "Bad NEAT socket descriptor %d\n", sd);
      abort();
   }
   return(rserpoolSocket);
}


/* ###### Notify main loop ############################################### */
void nsa_notify_main_loop()
{
   const ssize_t result = write(gSocketAPIInternals->main_loop_pipe[1], "!", 1);
   if(result <= 0) {
      perror("Writing to main loop pipe failed");
   }
}


/* ###### Main loop ###################################################### */
static void* nsa_main_loop(void* args)
{
   /* Get the underlying single file descriptor from libuv. Wait on this
      descriptor to become readable to know when to ask NEAT to run another
      loop ONCE on everything that it might have to work on. */
   const int backendFD = neat_get_backend_fd(gSocketAPIInternals->neat_context);

   /* kick off the event loop first */
// ???? Is this really necessary here? ????
   pthread_mutex_lock(&gSocketAPIInternals->socket_set_mutex);
   neat_start_event_loop(gSocketAPIInternals->neat_context, NEAT_RUN_ONCE);
   pthread_mutex_unlock(&gSocketAPIInternals->socket_set_mutex);


   puts("MAIN LOOP START!");

   for(;;) {
      /* ====== Prepare parameters for poll() ============================ */
      pthread_mutex_lock(&gSocketAPIInternals->socket_set_mutex);

      const bool    isShuttingDown = gSocketAPIInternals->main_loop_thread_shutdown;
      int           timeout        = neat_get_backend_timeout(gSocketAPIInternals->neat_context);

      const int     nfds = 2;
      struct pollfd ufds[nfds];
      ufds[0].fd      = gSocketAPIInternals->main_loop_pipe[0];   /* The wake-up pipe */
      ufds[0].events  = POLLIN;
      ufds[0].revents = 0;
      ufds[1].fd      = backendFD;   /* The back-end */
      ufds[1].events  = POLLERR|POLLIN|POLLHUP;
      ufds[1].revents = 0;

      pthread_mutex_unlock(&gSocketAPIInternals->socket_set_mutex);


      /* ====== Call poll() ============================================== */
      if(isShuttingDown) {
         break;
      }
      int results = poll((struct pollfd*)&ufds, nfds, timeout);


      /* ====== Handle poll() results ==================================== */
      if(results > 0) {
         if(ufds[0].revents & POLLIN) {   /* The wake-up pipe */
            char      buffer[128];
            const int r = read(gSocketAPIInternals->main_loop_pipe[0],
                               (char*)&buffer, sizeof(buffer));
            printf("MAIN LOOP WAKE-UP: r=%d\n", r);
         }
      }

      pthread_mutex_lock(&gSocketAPIInternals->socket_set_mutex);
      neat_start_event_loop(gSocketAPIInternals->neat_context, NEAT_RUN_ONCE);
      pthread_mutex_unlock(&gSocketAPIInternals->socket_set_mutex);
   }

   puts("MAIN LOOP STOP!");

   return(NULL);
}
