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

#include "eventsignal.h"

#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <sys/time.h>


/* ###### Constructor #################################################### */
void es_new(struct event_signal* es, struct event_signal* parent)
{
   /* ====== Initialise mutex ============================================ */
   pthread_mutexattr_t attributes;
   pthread_mutexattr_init(&attributes);
   pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE);
   pthread_mutex_init(&es->es_mutex, &attributes);
   pthread_mutexattr_destroy(&attributes);

   /* ====== Initialise condition ======================================== */
   pthread_cond_init(&es->es_condition, NULL);

   /* ====== Initialise attributes ======================================= */
   es->es_has_fired = false;
   TAILQ_INIT(&es->es_parent_list);
   es_add_parent(es, parent);
}


/* ###### Destructor ##################################################### */
void es_delete(struct event_signal* es)
{
   struct event_signal_node* esn;
   while( (esn = TAILQ_FIRST(&es->es_parent_list)) != NULL ) {
      TAILQ_REMOVE(&es->es_parent_list, esn, esn_node);
      free(esn);
   }
   pthread_cond_destroy(&es->es_condition);
   pthread_mutex_destroy(&es->es_mutex);
}


/* ###### Add parent ##################################################### */
void es_add_parent(struct event_signal* es, struct event_signal* parent)
{
   if(parent) {
      pthread_mutex_lock(&es->es_mutex);

      struct event_signal_node* esn = (struct event_signal_node*)malloc(sizeof(struct event_signal_node));
      assert(esn != NULL);
      esn->esn_event_signal_ptr = parent;
      TAILQ_INSERT_TAIL(&es->es_parent_list, esn, esn_node);

      if(es->es_has_fired) {
         es_broadcast(parent);
      }
      pthread_mutex_unlock(&es->es_mutex);
   }
}


/* ###### Remove parent ################################################## */
void es_remove_parent(struct event_signal* es, struct event_signal* parent)
{
   if(parent) {
      pthread_mutex_lock(&es->es_mutex);
      struct event_signal_node* esn;
      TAILQ_FOREACH(esn, &es->es_parent_list, esn_node) {
         if(esn->esn_event_signal_ptr == parent) {
            TAILQ_REMOVE(&es->es_parent_list, esn, esn_node);
            free(esn);
            break;
         }
      }
      pthread_mutex_unlock(&es->es_mutex);
   }
}


/* ###### Fire ########################################################### */
void es_fire(struct event_signal* es, const bool broadcast)
{
   pthread_mutex_lock(&es->es_mutex);

   /* ====== Fire condition ============================================== */
   es->es_has_fired = true;
   pthread_cond_signal(&es->es_condition);

   /* ====== Recursively fire parent conditions ========================== */
   struct event_signal_node* esn;
   TAILQ_FOREACH(esn, &es->es_parent_list, esn_node) {
      es_fire(esn->esn_event_signal_ptr, broadcast);
   }

   pthread_mutex_unlock(&es->es_mutex);
}


/* ###### Check whether condition has fired and reset its status ######### */
bool es_has_fired(struct event_signal* es)
{
   pthread_mutex_lock(&es->es_mutex);
   const bool hasFired = es->es_has_fired;
   es->es_has_fired = false;
   pthread_mutex_unlock(&es->es_mutex);
   return(hasFired);
}


/* ###### Check whether condition has fired ############################## */
bool es_peek_has_fired(struct event_signal* es)
{
   pthread_mutex_lock(&es->es_mutex);
   const bool hasFired = es->es_has_fired;
   pthread_mutex_unlock(&es->es_mutex);
   return(hasFired);
}


// ###### Wait for condition ############################################# */
void es_wait(struct event_signal* es)
{
   pthread_mutex_lock(&es->es_mutex);
   if(!es->es_has_fired) {
      pthread_cond_wait(&es->es_condition, &es->es_mutex);
   }
   pthread_mutex_unlock(&es->es_mutex);
}


// ###### Wait for condition with timeout ################################ */
bool es_timed_wait(struct event_signal* es, const long microseconds)
{
   pthread_mutex_lock(&es->es_mutex);
   if(!es->es_has_fired) {
      /* ====== Initialize timeout settings ============================== */
      struct timeval  now;
      struct timespec timeout;
      gettimeofday(&now,NULL);
      timeout.tv_sec  = now.tv_sec + (long)(microseconds / 1000000);
      timeout.tv_nsec = (now.tv_usec + (long)(microseconds % 1000000)) * 1000;
      if(timeout.tv_nsec >= 1000000000) {
         timeout.tv_sec++;
         timeout.tv_nsec -= 1000000000;
      }

      /* ====== Wait ===================================================== */
      pthread_cond_timedwait(&es->es_condition, &es->es_mutex, &timeout);
   }
   const bool hasFired = es->es_has_fired;
   es->es_has_fired = false;
   pthread_mutex_unlock(&es->es_mutex);

   return(hasFired);
}
