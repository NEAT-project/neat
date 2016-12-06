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

#include <notificationqueue.h>

#include <stddef.h>
#include <stdlib.h>


/* ###### Constructor #################################################### */
void nqn_new(struct notification_queue_node* notificationNode)
{
   notificationNode->nqn_next = NULL;
}


/* ###### Destructor ##################################################### */
void nqn_delete(struct notification_queue_node* notificationNode)
{
   notificationNode->nqn_next = NULL;
   free(notificationNode);
}


/* ###### Constructor #################################################### */
void nq_new(struct notification_queue* nq)
{
   nq->nq_pre_read_queue  = NULL;
   nq->nq_pre_read_last   = NULL;
   nq->nq_post_read_queue = NULL;
   nq->nq_post_read_last  = NULL;
   nq->nq_event_mask      = 0;
}


/* ###### Destructor ##################################################### */
void nq_delete(struct notification_queue* nq)
{
   nq_clear(nq);
}


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
