/*
 * Socket API implementation for NEAT
 * Copyright (C) 2016-2020 by Thomas Dreibholz <dreibh@simula.no>
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

#ifndef REDBLACKTREE_H
#define REDBLACKTREE_H

#include <stdio.h>


typedef unsigned long long redblacktree_node_value_type;

enum redblacktree_node_color_type
{
   Red   = 1,
   Black = 2
};


struct redblacktree_node
{
   struct redblacktree_node*          parent;
   struct redblacktree_node*          left_subtree;
   struct redblacktree_node*          right_subtree;
   enum redblacktree_node_color_type  color;
   redblacktree_node_value_type       value;
   redblacktree_node_value_type       value_sum;  /* value_sum := left_subtree->value + value + RightSubtree->value */
};

struct redblacktree
{
   struct redblacktree_node null_node;
   size_t                   elements;
   void                     (*print_function)(const void* node, FILE* fd);
   int                      (*comparison_function)(const void* node1, const void* node2);
};


#ifdef __cplusplus
extern "C" {
#endif

void rbt_node_new(struct redblacktree_node* node);
void rbt_node_delete(struct redblacktree_node* node);
int rbt_node_is_linked(const struct redblacktree_node* node);


void rbt_new(struct redblacktree* rbt,
             void                 (*printFunction)(const void* node, FILE* fd),
             int                  (*comparisonFunction)(const void* node1, const void* node2));
void rbt_delete(struct redblacktree* rbt);
void rbt_verify(struct redblacktree* rbt);
void rbt_print(const struct redblacktree* rbt,
               FILE*                      fd);
int rbt_is_empty(const struct redblacktree* rbt);
struct redblacktree_node* rbt_get_first(const struct redblacktree* rbt);
struct redblacktree_node* rbt_get_last(const struct redblacktree* rbt);
struct redblacktree_node* rbt_get_prev(const struct redblacktree*     rbt,
                                       const struct redblacktree_node* node);
struct redblacktree_node* rbt_get_next(const struct redblacktree*      rbt,
                                       const struct redblacktree_node* node);
struct redblacktree_node* rbt_get_nearest_prev(const struct redblacktree*      rbt,
                                               const struct redblacktree_node* cmpNode);
struct redblacktree_node* rbt_get_nearest_next(const struct redblacktree*      rbt,
                                               const struct redblacktree_node* cmpNode);
size_t rbt_get_elements(const struct redblacktree* rbt);
struct redblacktree_node* rbt_insert(struct redblacktree*      rbt,
                                     struct redblacktree_node* node);
struct redblacktree_node* rbt_remove(struct redblacktree*      rbt,
                                     struct redblacktree_node* node);
struct redblacktree_node* rbt_find(const struct redblacktree*      rbt,
                                   const struct redblacktree_node* cmpNode);
redblacktree_node_value_type rbt_get_value_sum(const struct redblacktree* rbt);
struct redblacktree_node* rbt_get_node_by_value(const struct redblacktree*    rbt,
                                                redblacktree_node_value_type  value);

#ifdef __cplusplus
}
#endif

#endif
