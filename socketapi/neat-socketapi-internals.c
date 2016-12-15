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
#include <string.h>
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


/* ###### Get socklen for given address ################################## */
size_t get_socklen(const struct sockaddr* address)
{
   switch(address->sa_family) {
      case AF_INET:
         return(sizeof(struct sockaddr_in));
      case AF_INET6:
         return(sizeof(struct sockaddr_in6));
      default:
         return(0);
   }
}


/* ###### Get port ####################################################### */
int get_port(const struct sockaddr* address)
{
   if(address != NULL) {
      switch(address->sa_family) {
         case AF_INET:
            return((int)ntohs(((struct sockaddr_in*)address)->sin_port));
         case AF_INET6:
            return((int)ntohs(((struct sockaddr_in6*)address)->sin6_port));
      }
   }
   return(-1);
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
      gSocketAPIInternals->nsi_main_loop_pipe[0] = -1;
      gSocketAPIInternals->nsi_main_loop_pipe[1] = -1;
      init_mutex(&gSocketAPIInternals->nsi_socket_set_mutex);
      rbt_new(&gSocketAPIInternals->nsi_socket_set,
              nsa_socket_print_function,
              nsa_socket_comparison_function);

      /* ====== Initialize identifier bitmap ============================= */
      gSocketAPIInternals->nsi_socket_identifier_bitmap = ibm_new(FD_SETSIZE);
      if(gSocketAPIInternals->nsi_socket_identifier_bitmap != NULL) {
         /* ====== NEAT context ========================================== */
         gSocketAPIInternals->nsi_neat_context = neat_init_ctx();
         if(gSocketAPIInternals->nsi_neat_context != NULL) {
            /* ====== Map stdin, stdout, stderr file descriptors ========= */
            assert(nsa_map_socket(STDOUT_FILENO, STDOUT_FILENO) == STDOUT_FILENO);
            assert(nsa_map_socket(STDIN_FILENO,  STDIN_FILENO)  == STDIN_FILENO);
            assert(nsa_map_socket(STDERR_FILENO, STDERR_FILENO) == STDERR_FILENO);

            /* ====== Initialize main loop =============================== */
            if(pipe((int*)&gSocketAPIInternals->nsi_main_loop_pipe) >= 0) {
               set_non_blocking(gSocketAPIInternals->nsi_main_loop_pipe[0]);
               set_non_blocking(gSocketAPIInternals->nsi_main_loop_pipe[1]);

               pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
               gSocketAPIInternals->nsi_main_loop_thread_shutdown = false;
               pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);

               if(pthread_create(&gSocketAPIInternals->nsi_main_loop_thread, NULL, &nsa_main_loop, gSocketAPIInternals) == 0) {
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


/* ###### Clean up ####################################################### */
void nsa_cleanup()
{
   if(gSocketAPIInternals) {
      /*
      pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
      struct neat_socket* neatSocket = (struct neat_socket*)rbt_get_first(&gSocketAPIInternals->nsi_socket_set);
      while(neatSocket != NULL) {
         printf("XXXXX sd=%d\n", neatSocket->ns_descriptor);
         nsa_close(neatSocket->ns_descriptor);
         neatSocket = (struct neat_socket*)rbt_get_first(&gSocketAPIInternals->nsi_socket_set);
      }
      pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
      */

      if(gSocketAPIInternals->nsi_main_loop_thread != 0) {
         pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
         gSocketAPIInternals->nsi_main_loop_thread_shutdown = true;
         pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
         nsa_notify_main_loop();
         assert(pthread_join(gSocketAPIInternals->nsi_main_loop_thread, NULL) == 0);
         gSocketAPIInternals->nsi_main_loop_thread = 0;
      }
      if(gSocketAPIInternals->nsi_main_loop_pipe[0] >= 0) {
         close(gSocketAPIInternals->nsi_main_loop_pipe[0]);
         gSocketAPIInternals->nsi_main_loop_pipe[0] = -1;
      }
      if(gSocketAPIInternals->nsi_main_loop_pipe[1] >= 0) {
         close(gSocketAPIInternals->nsi_main_loop_pipe[1]);
         gSocketAPIInternals->nsi_main_loop_pipe[1] = -1;
      }
      nsa_unmap_socket(STDERR_FILENO);
      nsa_unmap_socket(STDIN_FILENO);
      nsa_unmap_socket(STDOUT_FILENO);
      if(gSocketAPIInternals->nsi_neat_context) {
         neat_free_ctx(gSocketAPIInternals->nsi_neat_context);
         gSocketAPIInternals->nsi_neat_context = NULL;
      }
      if(gSocketAPIInternals->nsi_socket_identifier_bitmap)  {
         ibm_delete(gSocketAPIInternals->nsi_socket_identifier_bitmap);
         gSocketAPIInternals->nsi_socket_identifier_bitmap = NULL;
      }
      rbt_delete(&gSocketAPIInternals->nsi_socket_set);
      pthread_mutex_destroy(&gSocketAPIInternals->nsi_socket_set_mutex);
      free(gSocketAPIInternals);
      gSocketAPIInternals = NULL;
   }
}


/* ###### NEAT on_error() callback ####################################### */
static neat_error_code on_error(struct neat_flow_operations* ops)
{
   struct neat_socket* neatSocket = (struct neat_socket*)ops->userData;
   assert(neatSocket != NULL);

   pthread_mutex_lock(&neatSocket->ns_mutex);
   neatSocket->ns_flags |= NSAF_BAD;
   puts("on_error");
   es_broadcast(&neatSocket->ns_read_signal);
   pthread_mutex_unlock(&neatSocket->ns_mutex);

   return(NEAT_OK);
}


/* ###### NEAT on_connected() callback ################################### */
static neat_error_code on_connected(struct neat_flow_operations* ops)
{
   neat_error_code     result     = NEAT_OK;
   struct neat_socket* neatSocket = (struct neat_socket*)ops->userData;
   assert(neatSocket != NULL);

   pthread_mutex_lock(&neatSocket->ns_mutex);

   /* ====== Handle neat socket ===================================== */
   if(neatSocket->ns_flags & NSAF_LISTENING) {
      const int newSD = nsa_socket_internal(0, 0, 0, 0, ops->flow, -1);
      if(newSD >= 0) {
         struct neat_socket* newSocket = nsa_get_socket_for_descriptor(newSD);
         assert(newSocket != NULL);

         neat_set_operations(gSocketAPIInternals->nsi_neat_context,
                             newSocket->ns_flow, &newSocket->ns_flow_ops);

         TAILQ_INSERT_TAIL(&neatSocket->ns_accept_list,
                           newSocket, ns_accept_node);

         es_broadcast(&neatSocket->ns_read_signal);
      }
      else {
         perror("nsa_socket_internal() failed");
         neat_abort(gSocketAPIInternals->nsi_neat_context, ops->flow);
         result = NEAT_ERROR_INTERNAL;
      }
   }

   /* ====== Handle connecting socket ==================================== */
   else {
      neatSocket->ns_flags |= NSAF_CONNECTED;
      es_broadcast(&neatSocket->ns_read_signal);
   }

   pthread_mutex_unlock(&neatSocket->ns_mutex);
   return(result);
}


/* ###### NEAT on_readable() callback #################################### */
static neat_error_code on_readable(struct neat_flow_operations* ops)
{
   struct neat_socket* neatSocket = (struct neat_socket*)ops->userData;
   assert(neatSocket != NULL);
   pthread_mutex_lock(&neatSocket->ns_mutex);
   neatSocket->ns_flags |= NSAF_READABLE;
   puts("on_readable");
   es_broadcast(&neatSocket->ns_read_signal);
   nsa_set_socket_event_on_read(neatSocket, false);
   pthread_mutex_unlock(&neatSocket->ns_mutex);
   return(NEAT_OK);
}


/* ###### NEAT on_writable() callback #################################### */
static neat_error_code on_writable(struct neat_flow_operations* ops)
{
   struct neat_socket* neatSocket = (struct neat_socket*)ops->userData;
   assert(neatSocket != NULL);

   pthread_mutex_lock(&neatSocket->ns_mutex);
   neatSocket->ns_flags |= NSAF_WRITABLE;
   puts("on_writable");
   es_broadcast(&neatSocket->ns_write_signal);
   nsa_set_socket_event_on_write(neatSocket, false);
   pthread_mutex_unlock(&neatSocket->ns_mutex);

   return(NEAT_OK);
}


/* ###### NEAT on_all_written() callback ################################# */
static neat_error_code on_all_written(struct neat_flow_operations* ops)
{
   struct neat_socket* neatSocket = (struct neat_socket*)ops->userData;
   assert(neatSocket != NULL);

   pthread_mutex_lock(&neatSocket->ns_mutex);
   neatSocket->ns_flags |= NSAF_WRITABLE;
   puts("on_all_written");
   es_broadcast(&neatSocket->ns_write_signal);
   nsa_set_socket_event_on_write(neatSocket, false);
   pthread_mutex_unlock(&neatSocket->ns_mutex);

   return(NEAT_OK);
}


/* ###### NEAT on_network_status_changed() callback ###################### */
static neat_error_code on_network_status_changed(struct neat_flow_operations* ops)
{
   struct neat_socket* neatSocket = (struct neat_socket*)ops->userData;
   assert(neatSocket != NULL);

   pthread_mutex_lock(&neatSocket->ns_mutex);
   puts("on_network_status_changed");
   pthread_mutex_unlock(&neatSocket->ns_mutex);

   return(NEAT_OK);
}


/* ###### NEAT on_aborted() callback ##################################### */
static neat_error_code on_aborted(struct neat_flow_operations* ops)
{
   struct neat_socket* neatSocket = (struct neat_socket*)ops->userData;
   assert(neatSocket != NULL);

   pthread_mutex_lock(&neatSocket->ns_mutex);
   neatSocket->ns_flags |= NSAF_BAD;
   puts("on_aborted");
   pthread_mutex_unlock(&neatSocket->ns_mutex);

   return(NEAT_OK);
}


/* ###### NEAT on_timeout() callback ##################################### */
static neat_error_code on_timeout(struct neat_flow_operations* ops)
{
   struct neat_socket* neatSocket = (struct neat_socket*)ops->userData;
   assert(neatSocket != NULL);

   pthread_mutex_lock(&neatSocket->ns_mutex);
   neatSocket->ns_flags |= NSAF_BAD;
   puts("on_timeout");
   pthread_mutex_unlock(&neatSocket->ns_mutex);

   return(NEAT_OK);
}


/* ###### NEAT on_close() callback ####################################### */
static neat_error_code on_close(struct neat_flow_operations* ops)
{
   struct neat_socket* neatSocket = (struct neat_socket*)ops->userData;
   assert(neatSocket != NULL);

   puts("on_close");
   nsa_close_internal(neatSocket);

   return(NEAT_OK);
}


/* ###### NEAT on_send_failure() callback ################################ */
static void on_send_failure(struct neat_flow_operations* ops,
                            int context, const unsigned char* unsent)
{
   struct neat_socket* neatSocket = (struct neat_socket*)ops->userData;
   assert(neatSocket != NULL);

   pthread_mutex_lock(&neatSocket->ns_mutex);
   neatSocket->ns_flags |= NSAF_BAD;
   puts("on_send_failure");
   pthread_mutex_unlock(&neatSocket->ns_mutex);
}


/* ###### NEAT on_slowdown() callback #################################### */
static void on_slowdown(struct neat_flow_operations* ops, int ecn, uint32_t rate)
{
   struct neat_socket* neatSocket = (struct neat_socket*)ops->userData;
   assert(neatSocket != NULL);

   pthread_mutex_lock(&neatSocket->ns_mutex);
   puts("on_slowdown");
   pthread_mutex_unlock(&neatSocket->ns_mutex);
}


/* ###### NEAT on_rate_hint() callback ################################### */
static void on_rate_hint(struct neat_flow_operations* ops, uint32_t new_rate)
{
   struct neat_socket* neatSocket = (struct neat_socket*)ops->userData;
   assert(neatSocket != NULL);

   pthread_mutex_lock(&neatSocket->ns_mutex);
   puts("on_rate_hint");
   pthread_mutex_unlock(&neatSocket->ns_mutex);
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

   if(flow != NULL) {   /* NEAT flow */
      neatSocket->ns_socket_sd = -1;
      neatSocket->ns_flow      = flow;

      memset(&neatSocket->ns_flow_ops, 0, sizeof(neatSocket->ns_flow_ops));
      neatSocket->ns_flow_ops.userData                  = neatSocket;
      neatSocket->ns_flow_ops.on_error                  = &on_error;
      neatSocket->ns_flow_ops.on_connected              = &on_connected;
      neatSocket->ns_flow_ops.on_readable               = &on_readable;
      neatSocket->ns_flow_ops.on_writable               = &on_writable;
      neatSocket->ns_flow_ops.on_all_written            = &on_all_written;
      neatSocket->ns_flow_ops.on_network_status_changed = &on_network_status_changed;
      neatSocket->ns_flow_ops.on_aborted                = &on_aborted;
      neatSocket->ns_flow_ops.on_timeout                = &on_timeout;
      neatSocket->ns_flow_ops.on_close                  = &on_close;
      neatSocket->ns_flow_ops.on_send_failure           = &on_send_failure;
      neatSocket->ns_flow_ops.on_slowdown               = &on_slowdown;
      neatSocket->ns_flow_ops.on_rate_hint              = &on_rate_hint;
      neat_set_operations(gSocketAPIInternals->nsi_neat_context,
                          neatSocket->ns_flow, &neatSocket->ns_flow_ops);
   }
   else if(customFD < 0) {   /* System socket to be created */
      neatSocket->ns_socket_sd = socket(domain, type, protocol);
      neatSocket->ns_flags |= NSAF_CLOSE_ON_REMOVAL;
   }
   else {   /* Existing socket, given by its socket descriptor */
      neatSocket->ns_socket_sd = customFD;
   }

   /* ====== Set socket into non-blocking mode =========================== */
   if(neatSocket->ns_socket_sd >= 0) {
      set_non_blocking(neatSocket->ns_socket_sd);
   }

   /* ====== Initialize NEAT socket ====================================== */
   rbt_node_new(&neatSocket->ns_node);
   es_new(&neatSocket->ns_read_signal, NULL);
   es_new(&neatSocket->ns_write_signal, NULL);
   es_new(&neatSocket->ns_exception_signal, NULL);
   nq_new(&neatSocket->ns_notifications);
   init_mutex(&neatSocket->ns_mutex);
   neatSocket->ns_descriptor      = -1;   /* to be allocated below */
   neatSocket->ns_socket_domain   = domain;
   neatSocket->ns_socket_type     = type;
   neatSocket->ns_socket_protocol = protocol;
   TAILQ_INIT(&neatSocket->ns_accept_list);

   /* ====== Add new socket to socket storage ============================ */
   pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
   if(requestedSD < 0) {
      neatSocket->ns_descriptor = ibm_allocate_id(gSocketAPIInternals->nsi_socket_identifier_bitmap);
   }
   else {
      neatSocket->ns_descriptor = ibm_allocate_specific_id(gSocketAPIInternals->nsi_socket_identifier_bitmap,
                                                           requestedSD);
   }
   if(neatSocket->ns_descriptor >= 0) {
      assert(rbt_insert(&gSocketAPIInternals->nsi_socket_set, &neatSocket->ns_node) == &neatSocket->ns_node);
   }
   pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);

   /* ====== Has there been a problem? =================================== */
   if(neatSocket->ns_descriptor < 0) {
      if(neatSocket->ns_flags & NSAF_CLOSE_ON_REMOVAL) {
         close(neatSocket->ns_socket_sd);
      }
      pthread_mutex_destroy(&neatSocket->ns_mutex);
      free(neatSocket);
      errno = EMFILE;
      return(-1);
   }
   return(neatSocket->ns_descriptor);
}


/* ###### NEAT close() implementation #################################### */
void nsa_close_internal(struct neat_socket* neatSocket)
{
   /* NOTE: gSocketAPIInternals->nsi_socket_set_mutex must already
    *       be obtained when calling nsa_close_internal()! */

   pthread_mutex_lock(&neatSocket->ns_mutex);

   /* ====== Close accepted sockets first ================================ */
   struct neat_socket* acceptedSocket;
   while( (acceptedSocket = TAILQ_FIRST(&neatSocket->ns_accept_list)) != NULL ) {
      TAILQ_REMOVE(&neatSocket->ns_accept_list, acceptedSocket, ns_accept_node);
      nsa_close(acceptedSocket->ns_descriptor);
   }

   /* ====== Close socket ================================================ */
   if(neatSocket->ns_flow != NULL) {
      /* neat_close() was already called. This code is supposed to be run
       * in on_close() callback! */
      neatSocket->ns_flow = NULL;
   }
   else if(neatSocket->ns_socket_sd >= 0) {
      if(neatSocket->ns_flags & NSAF_CLOSE_ON_REMOVAL) {
         close(neatSocket->ns_socket_sd);
      }
      neatSocket->ns_socket_sd = -1;
   }

   /* ====== Remove socket ===============================================*/
   if(rbt_node_is_linked(&neatSocket->ns_node)) {
      rbt_remove(&gSocketAPIInternals->nsi_socket_set, &neatSocket->ns_node);
   }
   ibm_free_id(gSocketAPIInternals->nsi_socket_identifier_bitmap, neatSocket->ns_descriptor);
   neatSocket->ns_descriptor = -1;

   nq_delete(&neatSocket->ns_notifications);
   es_delete(&neatSocket->ns_exception_signal);
   es_delete(&neatSocket->ns_write_signal);
   es_delete(&neatSocket->ns_read_signal);
   pthread_mutex_unlock(&neatSocket->ns_mutex);
   pthread_mutex_destroy(&neatSocket->ns_mutex);
   free(neatSocket);
}


/* ###### Enable/disable socket event on read ############################ */
void nsa_set_socket_event_on_read(struct neat_socket* neatSocket, const bool r)
{
   neatSocket->ns_flow_ops.on_readable = (r) ? &on_readable : NULL;
}


/* ###### Enable/disable socket event on write ########################### */
void nsa_set_socket_event_on_write(struct neat_socket* neatSocket, const bool w)
{
   neatSocket->ns_flow_ops.on_writable = (w) ? &on_writable : NULL;
   neat_set_operations(gSocketAPIInternals->nsi_neat_context,
                       neatSocket->ns_flow, &neatSocket->ns_flow_ops);
}


/* ###### Print socket ################################################### */
void nsa_socket_print_function(const void* node, FILE* fd)
{
   const struct neat_socket* neatSocket = (const struct neat_socket*)node;
   fprintf(fd, "%d ", neatSocket->ns_descriptor);
}


/* ###### Compare sockets ################################################ */
int nsa_socket_comparison_function(const void* node1, const void* node2)
{
   const struct neat_socket* neatSocket1 = (const struct neat_socket*)node1;
   const struct neat_socket* neatSocket2 = (const struct neat_socket*)node2;

   if(neatSocket1->ns_descriptor < neatSocket2->ns_descriptor) {
      return(-1);
   }
   else if(neatSocket1->ns_descriptor > neatSocket2->ns_descriptor) {
      return(1);
   }
   return(0);
}


/* ###### Find socket #################################################### */
struct neat_socket* nsa_get_socket_for_descriptor(int sd)
{
   struct neat_socket* neatSocket;
   struct neat_socket  cmpSocket;

   cmpSocket.ns_descriptor = sd;
   pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
   neatSocket = (struct neat_socket*)rbt_find(&gSocketAPIInternals->nsi_socket_set,
                                              &cmpSocket.ns_node);
   pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
   return(neatSocket);
}


/* ###### Wait until there is something to read ########################## */
int nsa_wait_for_event(struct neat_socket* neatSocket,
                       int                 eventMask,
                       int                 timeout)
{
   struct pollfd ufds[1];
   ufds[0].fd     = neatSocket->ns_descriptor;
   ufds[0].events = POLLIN;
   int result = nsa_poll((struct pollfd*)&ufds, 1, timeout);
   if((result > 0) && (ufds[0].revents & eventMask)) {
      return(ufds[0].revents);
   }
   return(0);
}


/* ###### Notify main loop ############################################### */
void nsa_notify_main_loop()
{
   const ssize_t result = write(gSocketAPIInternals->nsi_main_loop_pipe[1], "!", 1);
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
   const int backendFD = neat_get_backend_fd(gSocketAPIInternals->nsi_neat_context);

   /* kick off the event loop first */
// ???? Is this really necessary here? ????
   pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
   neat_start_event_loop(gSocketAPIInternals->nsi_neat_context, NEAT_RUN_ONCE);
   pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);


   puts("MAIN LOOP START!");

   for(;;) {
      /* ====== Prepare parameters for poll() ============================ */
      pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);

      const bool    isShuttingDown = gSocketAPIInternals->nsi_main_loop_thread_shutdown;
      int           timeout        = neat_get_backend_timeout(gSocketAPIInternals->nsi_neat_context);

      const int     nfds = 2;
      struct pollfd ufds[nfds];
      ufds[0].fd      = gSocketAPIInternals->nsi_main_loop_pipe[0];   /* The wake-up pipe */
      ufds[0].events  = POLLIN;
      ufds[0].revents = 0;
      ufds[1].fd      = backendFD;   /* The back-end */
      ufds[1].events  = POLLERR|POLLIN|POLLHUP;
      ufds[1].revents = 0;

      pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);


      /* ====== Call poll() ============================================== */
      if(isShuttingDown) {
         break;
      }
      int results = poll((struct pollfd*)&ufds, nfds, timeout);


      /* ====== Handle poll() results ==================================== */
      if(results > 0) {
         if(ufds[0].revents & POLLIN) {   /* The wake-up pipe */
            char      buffer[128];
            const int r = read(gSocketAPIInternals->nsi_main_loop_pipe[0],
                               (char*)&buffer, sizeof(buffer));
            printf("MAIN LOOP WAKE-UP: r=%d\n", r);
         }
      }

      pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
      neat_start_event_loop(gSocketAPIInternals->nsi_neat_context, NEAT_RUN_ONCE);
      pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
   }

   puts("MAIN LOOP STOP!");

   return(NULL);
}
