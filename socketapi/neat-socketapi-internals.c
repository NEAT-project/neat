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


struct neat_socketapi_internals* gSocketAPIInternals = NULL;


/* ###### Initialize recursive mutex ##################################### */
static void init_mutex(pthread_mutex_t* mutex)
{
   pthread_mutexattr_t attributes;
   pthread_mutexattr_init(&attributes);
   pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE);
   pthread_mutex_init(mutex, &attributes);
   pthread_mutexattr_destroy(&attributes);
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
      init_mutex(&gSocketAPIInternals->socket_set_mutex);
      rbt_new(&gSocketAPIInternals->socket_set,
              nsa_socket_print_function,
              nsa_socket_comparison_function);

      /* ====== Initialize identifier bitmap ============================= */
      gSocketAPIInternals->socket_identifier_bitmap = ibm_new(FD_SETSIZE);
      if(gSocketAPIInternals->socket_identifier_bitmap != NULL) {


         /* ====== NEAT context ========================================== */
         gSocketAPIInternals->neat_context = neat_init_ctx();
         if(gSocketAPIInternals->neat_context != NULL) {

            puts("READY!");

            return(gSocketAPIInternals);
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
      puts("CLEAN!");
   }
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
