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

#ifndef NEAT_SOCKETAPI_INTERNALS_H
#define NEAT_SOCKETAPI_INTERNALS_H


#include <neat-socketapi.h>
#include <neat.h>

#include <stdbool.h>
#include <pthread.h>

#include "redblacktree.h"
#include "identifierbitmap.h"
#include "notificationqueue.h"


struct neat_socketapi_internals
{
   /* ====== NEAT Core ================================= */
   struct neat_ctx*          neat_context;

   /* ====== Socket Storage ============================ */
   struct identifier_bitmap* socket_identifier_bitmap;
   struct redblacktree       socket_set;
   pthread_mutex_t           socket_set_mutex;

   /* ====== Main loop ================================= */
   pthread_t                 main_loop_thread;
   bool                      main_loop_thread_shutdown;
   int                       main_loop_pipe[2];
};


#define NSAF_READABLE         (1 << 0)
#define NSAF_WRITABLE         (1 << 1)
#define NSAF_CONNECTED        (1 << 2)
#define NSAF_BAD              (1 << 3)

#define NSAF_NONBLOCKING      (1 << 6)
#define NSAF_CLOSE_ON_REMOVAL (1 << 7)

struct neat_socket
{
   struct redblacktree_node    node;
   pthread_mutex_t             mutex;
   int                         descriptor;

   int                         flags;

   struct neat_flow*           flow;
   struct neat_flow_operations flow_ops;
   int                         socket_domain;
   int                         socket_type;
   int                         socket_protocol;
   int                         socket_sd;

   struct notification_queue   notifications;
};


#define GET_NEAT_SOCKET(fd) \
   struct neat_socket* neatSocket = nsa_get_socket_for_descriptor(fd); \
   if(neatSocket == NULL) { \
      errno = EBADF; \
      return(-1); \
   }


#ifdef __cplusplus
extern "C" {
#endif

extern struct neat_socketapi_internals* gSocketAPIInternals;


size_t get_socklen(const struct sockaddr* address);
int get_port(const struct sockaddr* address);

struct neat_socketapi_internals* nsa_initialize();
int nsa_socket_internal(int domain, int type, int protocol,
                        int customFD, struct neat_flow* flow, int requestedSD);
void nsa_notify_main_loop();

void nsa_socket_print_function(const void* node, FILE* fd);
int nsa_socket_comparison_function(const void* node1, const void* node2);
struct neat_socket* nsa_get_socket_for_descriptor(int sd);


#ifdef __cplusplus
}
#endif

#endif
