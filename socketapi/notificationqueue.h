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

#ifndef NOTIFICATIONQUEUE_H
#define NOTIFICATIONQUEUE_H

#include <neat-socketapi.h>

#include <stdbool.h>


/* Notification event types */
// #define NET_SESSION_CHANGE    (1 << RSERPOOL_SESSION_CHANGE)
// #define NET_FAILOVER          (1 << RSERPOOL_FAILOVER)
// #define NET_SHUTDOWN_EVENT    (1 << RSERPOOL_SHUTDOWN_EVENT)
// #define NET_NOTIFICATION_MASK (NET_SESSION_CHANGE|NET_FAILOVER|NET_SHUTDOWN_EVENT)


struct notification_queue_node
{
   struct notification_queue_node* nqn_next;
   union neat_notification         nqn_content;
};

struct notification_queue
{
   struct notification_queue_node* nq_pre_read_queue;
   struct notification_queue_node* nq_pre_read_last;
   struct notification_queue_node* nq_post_read_queue;
   struct notification_queue_node* nq_post_read_last;
   unsigned int                    nq_event_mask;
};


#ifdef __cplusplus
extern "C" {
#endif

void nqn_new(struct notification_queue_node* notificationNode);
void nqn_delete(struct notification_queue_node* notificationNode);

void nq_new(struct notification_queue* nq);
void nq_delete(struct notification_queue* nq);
void nq_clear(struct notification_queue* nq);
struct notification_queue_node* nq_enqueue(struct notification_queue* nq,
                                           const bool                 isPreReadNotification,
                                           const uint16_t             type);
struct notification_queue_node* nq_dequeue(struct notification_queue* nq,
                                           const bool                 fromPreReadNotifications);
bool nq_has_data(struct notification_queue* nq);

#ifdef __cplusplus
}
#endif

#endif
