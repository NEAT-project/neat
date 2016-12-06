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

#include <condition.h>

#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>


/* ###### Constructor #################################################### */
void es_new(struct event_signal* es, struct event_signal* parent);
{
   /* ====== Initialise mutex ============================================ */
   pthread_mutexattr_t attributes;
   pthread_mutexattr_init(&attributes);
   pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE);
   pthread_mutex_init(&es->mutex, &attributes);
   pthread_mutexattr_destroy(&attributes);

   /* ====== Initialise condition ======================================== */
   pthread_cond_init(&es->condition, NULL);

   es->es_fired = false;
   addParent(es, parent);
}


/* ###### Destructor ##################################################### */
void es_delete(struct event_signal* es);
{
}


/* ###### Add parent ##################################################### */
void es_add_parent(struct event_signal* es, struct event_signal* parent)
{
   if(parent) {
      pthread_mutex_lock(&es->mutex);

      INSERT ...

      if(es->fired) {
         es_broadcast(parent);
      }
      pthread_mutex_unlock(&es->mutex);
   }
}


/* ###### Remove parent ################################################## */
void es_remove_parent(struct event_signal* es, struct event_signal* parent)
{
   if(parent) {
      pthread_mutex_lock(&es->mutex);

REMOVE ...

      pthread_mutex_unlock(&es->mutex);
   }
}


/* ###### Fire # ######################################################### */
void es_signal(struct event_signal* es)
{
 
}


void es_broadcast(struct event_signal* es);
bool es_fired(struct event_signal* es);
bool es_peek_fired(struct event_signal* es);
void es_wait(struct event_signal* es);
void es_timed_wait(struct event_signal* es, int timeout);



/* ###### Clean up queue ################################################# */
void nq_clear(struct notification_queue* nq)
{
   struct notification_queue_node* next;

   while(nq->nq_pre_read_queue) {
      next = nq->nq_pre_read_queue->nqn_next;
      free(nq->nq_pre_read_queue);
      nq->nq_pre_read_queue = next;
   }
   nq->nq_pre_read_last = NULL;

   while(nq->nq_post_read_queue) {
      next = nq->nq_post_read_queue->nqn_next;
      free(nq->nq_post_read_queue);
      nq->nq_post_read_queue = next;
   }
   nq->nq_post_read_last = NULL;
}


/* ###### Check, if there are notifications to read ###################### */
bool nq_has_data(struct notification_queue* nq)
{
   return((nq->nq_pre_read_queue != NULL) ||
          (nq->nq_post_read_queue != NULL));
}


/* ###### Enqueue notification ########################################### */
struct notification_queue_node* nq_enqueue(
                                   struct notification_queue* nq,
                                   const bool                 isPreReadNotification,
                                   const uint16_t             type)
{
   struct notification_queue_node* notificationNode;

   /* ====== Only enqueue requested events =============================== */
   if((1 << type) & nq->nq_event_mask) {
      notificationNode = (struct notification_queue_node*)malloc(sizeof(struct notification_queue_node));
      if(notificationNode) {
         /* ====== Set pending events appropriately ====================== */
         nqn_new(notificationNode);
         notificationNode->nqn_content.nn_header.nn_type   = type;
         notificationNode->nqn_content.nn_header.nn_flags  = 0x00;
         notificationNode->nqn_content.nn_header.nn_length = sizeof(notificationNode->nqn_content);

         /* ====== Add notification node ================================= */
         if(isPreReadNotification) {
             if(nq->nq_pre_read_last) {
                nq->nq_pre_read_last->nqn_next = notificationNode;
             }
             else {
                nq->nq_pre_read_queue = notificationNode;
             }
             nq->nq_pre_read_last = notificationNode;
         }
         else {
             if(nq->nq_post_read_last) {
                nq->nq_post_read_last->nqn_next = notificationNode;
             }
             else {
                nq->nq_post_read_queue = notificationNode;
             }
             nq->nq_post_read_last = notificationNode;
         }
      }
   }
   else {
      notificationNode = NULL;
   }
   return(notificationNode);
}


/* ###### Dequeue notification ########################################### */
struct notification_queue_node* nq_dequeue(
                                   struct notification_queue* nq,
                                   const bool                 fromPreReadNotifications)
{
   struct notification_queue_node* notificationNode;

   if(fromPreReadNotifications) {
      notificationNode = nq->nq_pre_read_queue;
      if(notificationNode) {
         nq->nq_pre_read_queue = notificationNode->nqn_next;
      }
      if(notificationNode == nq->nq_pre_read_last) {
         nq->nq_pre_read_last = NULL;
      }
   }
   else {
      notificationNode = nq->nq_post_read_queue;
      if(notificationNode) {
         nq->nq_post_read_queue = notificationNode->nqn_next;
      }
      if(notificationNode == nq->nq_post_read_last) {
         nq->nq_post_read_last = NULL;
      }
   }
   return(notificationNode);
}
