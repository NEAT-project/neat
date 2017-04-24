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

#ifndef EVENTSIGNAL_H
#define EVENTSIGNAL_H

#include <stdbool.h>
#include <pthread.h>
#include <sys/queue.h>


struct event_signal;

struct event_signal_node
{
   TAILQ_ENTRY(event_signal_node) esn_node;
   struct event_signal*           esn_event_signal_ptr;
};

struct event_signal
{
   pthread_mutex_t                                         es_mutex;
   pthread_cond_t                                          es_condition;
   bool                                                    es_has_fired;
   TAILQ_HEAD(event_signal_node_header, event_signal_node) es_parent_list;
};


#ifdef __cplusplus
extern "C" {
#endif

void es_new(struct event_signal* es, struct event_signal* parent);
void es_delete(struct event_signal* es);

void es_add_parent(struct event_signal* es, struct event_signal* parent);
void es_remove_parent(struct event_signal* es, struct event_signal* parent);

void es_fire(struct event_signal* es, const bool broadcast);
inline void es_signal(struct event_signal* es) { es_fire(es, false); }
inline void es_broadcast(struct event_signal* es) { es_fire(es, true); }

bool es_has_fired(struct event_signal* es);
bool es_peek_fired(struct event_signal* es);
void es_wait(struct event_signal* es);
bool es_timed_wait(struct event_signal* es, const long microseconds);

#ifdef __cplusplus
}
#endif

#endif
