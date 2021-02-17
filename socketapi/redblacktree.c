/*
 * Socket API implementation for NEAT
 * Copyright (C) 2016-2021 by Thomas Dreibholz <dreibh@simula.no>
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

#include <redblacktree.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>


#ifdef __cplusplus
extern "C" {
#endif


static struct redblacktree_node* rbt_internal_find_prev(const struct redblacktree*      rbt,
                                                        const struct redblacktree_node* cmpNode);
static struct redblacktree_node* rbt_internal_find_next(const struct redblacktree*      rbt,
                                                        const struct redblacktree_node* cmpNode);


/* ###### Initialize ##################################################### */
void rbt_node_new(struct redblacktree_node* node)
{
   node->parent        = NULL;
   node->left_subtree  = NULL;
   node->right_subtree = NULL;
   node->color         = Black;
   node->value         = 0;
   node->value_sum     = 0;
}


/* ###### Invalidate ##################################################### */
void rbt_node_delete(struct redblacktree_node* node)
{
   node->parent        = NULL;
   node->left_subtree  = NULL;
   node->right_subtree = NULL;
   node->color         = Black;
   node->value         = 0;
   node->value_sum     = 0;
}


/* ###### Is node linked? ################################################ */
int rbt_node_is_linked(const struct redblacktree_node* node)
{
   return(node->left_subtree != NULL);
}


/* ##### Initialize ###################################################### */
void rbt_new(struct redblacktree* rbt,
             void                 (*printFunction)(const void* node, FILE* fd),
             int                  (*comparisonFunction)(const void* node1, const void* node2))
{
   rbt->print_function          = printFunction;
   rbt->comparison_function     = comparisonFunction;
   rbt->null_node.parent        = &rbt->null_node;
   rbt->null_node.left_subtree  = &rbt->null_node;
   rbt->null_node.right_subtree = &rbt->null_node;
   rbt->null_node.color         = Black;
   rbt->null_node.value         = 0;
   rbt->null_node.value_sum     = 0;
   rbt->elements                = 0;
}


/* ##### Invalidate ###################################################### */
void rbt_delete(struct redblacktree* rbt)
{
   rbt->elements                = 0;
   rbt->null_node.parent        = NULL;
   rbt->null_node.left_subtree  = NULL;
   rbt->null_node.right_subtree = NULL;
}


/* ##### Update value sum ################################################ */
inline static void rbt_update_value_sum(struct redblacktree_node* node)
{
   node->value_sum = node->left_subtree->value_sum + node->value + node->right_subtree->value_sum;
}


/* ##### Update value sum for node and all parents up to tree root ####### */
static void rbt_update_value_sums_up_to_root(struct redblacktree*      rbt,
                                             struct redblacktree_node* node)
{
   while(node != &rbt->null_node) {
       rbt_update_value_sum(node);
       node = node->parent;
   }
}


/* ###### Internal method for printing a node ############################ */
static void rbt_print_node(const struct redblacktree*      rbt,
                           const struct redblacktree_node* node,
                           FILE*                           fd)
{
   rbt->print_function(node, fd);
#ifdef DEBUG
   fprintf(fd, " ptr=%p c=%s v=%llu vsum=%llu",
           node, ((node->color == Red) ? "Red" : "Black"),
           node->value, node->value_sum);
   if(node->left_subtree != &rbt->null_node) {
      fprintf(fd, " l=%p[", node->left_subtree);
      rbt->print_function(node->left_subtree, fd);
      fprintf(fd, "]");
   }
   else {
      fprintf(fd, " l=()");
   }
   if(node->right_subtree != &rbt->null_node) {
      fprintf(fd, " r=%p[", node->right_subtree);
      rbt->print_function(node->right_subtree, fd);
      fprintf(fd, "]");
   }
   else {
      fprintf(fd, " r=()");
   }
   if(node->parent != &rbt->null_node) {
      fprintf(fd, " p=%p[", node->parent);
      rbt->print_function(node->parent, fd);
      fprintf(fd, "]   ");
   }
   else {
      fprintf(fd, " p=())   ");
   }
   fputs("\n", fd);
#endif
}


/* ##### Internal printing function ###################################### */
void rbt_internal_print(const struct redblacktree*      rbt,
                        const struct redblacktree_node* node,
                        FILE*                           fd)
{
   if(node != &rbt->null_node) {
      rbt_internal_print(rbt, node->left_subtree, fd);
      rbt_print_node(rbt, node, fd);
      rbt_internal_print(rbt, node->right_subtree, fd);
   }
}


/* ###### Print tree ##################################################### */
void rbt_print(const struct redblacktree* rbt,
               FILE*                      fd)
{
#ifdef DEBUG
   fprintf(fd, "\n\nroot=%p[", rbt->null_node.left_subtree);
   if(rbt->null_node.left_subtree != &rbt->null_node) {
      rbt->print_function(rbt->null_node.left_subtree, fd);
   }
   fprintf(fd, "] null=%p   \n", &rbt->null_node);
#endif
   rbt_internal_print(rbt, rbt->null_node.left_subtree, fd);
   fputs("\n", fd);
}


/* ###### Is tree empty? ################################################# */
int rbt_is_empty(const struct redblacktree* rbt)
{
   return(rbt->null_node.left_subtree == &rbt->null_node);
}


/* ###### Get first node ################################################## */
struct redblacktree_node* rbt_get_first(const struct redblacktree* rbt)
{
   const struct redblacktree_node* node = rbt->null_node.left_subtree;
   if(node == &rbt->null_node) {
      node = rbt->null_node.right_subtree;
   }
   while(node->left_subtree != &rbt->null_node) {
      node = node->left_subtree;
   }
   if(node != &rbt->null_node) {
      return((struct redblacktree_node*)node);
   }
   return(NULL);
}


/* ###### Get last node ################################################### */
struct redblacktree_node* rbt_get_last(const struct redblacktree* rbt)
{
   const struct redblacktree_node* node = rbt->null_node.right_subtree;
   if(node == &rbt->null_node) {
      node = rbt->null_node.left_subtree;
   }
   while(node->right_subtree != &rbt->null_node) {
      node = node->right_subtree;
   }
   if(node != &rbt->null_node) {
      return((struct redblacktree_node*)node);
   }
   return(NULL);
}


/* ###### Get previous node ############################################### */
struct redblacktree_node* rbt_get_prev(const struct redblacktree*      rbt,
                                       const struct redblacktree_node* node)
{
   struct redblacktree_node* result;
   result = rbt_internal_find_prev(rbt, node);
   if(result != &rbt->null_node) {
      return(result);
   }
   return(NULL);
}


/* ###### Get next node ################################################## */
struct redblacktree_node* rbt_get_next(const struct redblacktree*      rbt,
                                       const struct redblacktree_node* node)
{
   struct redblacktree_node* result;
   result = rbt_internal_find_next(rbt, node);
   if(result != &rbt->null_node) {
      return(result);
   }
   return(NULL);
}


/* ###### Find nearest previous node ##################################### */
struct redblacktree_node* rbt_get_nearest_prev(const struct redblacktree*      rbt,
                                               const struct redblacktree_node* cmpNode)
{
   struct redblacktree_node*const* nodePtr;
   struct redblacktree_node*const* parentPtr;
   const struct redblacktree_node* node;
   const struct redblacktree_node* parent;
   int                             cmpResult = 0;

#ifdef DEBUG
   printf("nearest prev: ");
   rbt->print_function(cmpNode, stdout);
   printf("\n");
   rbt_print(rbt, stdout);
#endif

   parentPtr = NULL;
   nodePtr   = &rbt->null_node.left_subtree;
   while(*nodePtr != &rbt->null_node) {
      cmpResult = rbt->comparison_function(cmpNode, *nodePtr);
      if(cmpResult < 0) {
         parentPtr = nodePtr;
         nodePtr   = &(*nodePtr)->left_subtree;
      }
      else if(cmpResult > 0) {
         parentPtr = nodePtr;
         nodePtr   = &(*nodePtr)->right_subtree;
      }
      if(cmpResult == 0) {
         return(rbt_get_prev(rbt, *nodePtr));
      }
   }

   if(parentPtr == NULL) {
      if(cmpResult > 0) {
         return(rbt->null_node.left_subtree);
      }
      return(NULL);
   }
   else {
      /* The new node would be the right child of its parent.
         => The parent is the nearest previous node! */
      if(nodePtr == &(*parentPtr)->right_subtree) {
         return(*parentPtr);
      }
      else {
         parent = *parentPtr;

         /* If there is a left subtree, the nearest previous node is the
            rightmost child of the left subtree. */
         if(parent->left_subtree != &rbt->null_node) {
            node = parent->left_subtree;
            while(node->right_subtree != &rbt->null_node) {
               node = node->right_subtree;
            }
            if(node != &rbt->null_node) {
               return((struct redblacktree_node*)node);
            }
         }

         /* If there is no left subtree, the nearest previous node is an
            ancestor node which has the node on its right side. */
         else {
            node   = parent;
            parent = node->parent;
            while((parent != &rbt->null_node) && (node == parent->left_subtree)) {
               node   = parent;
               parent = parent->parent;
            }
            if(parent != &rbt->null_node) {
               return((struct redblacktree_node*)parent);
            }
         }
      }
   }
   return(NULL);
}


/* ###### Find nearest next node ######################################### */
struct redblacktree_node* rbt_get_nearest_next(const struct redblacktree*      rbt,
                                               const struct redblacktree_node* cmpNode)
{
   struct redblacktree_node*const* nodePtr;
   struct redblacktree_node*const* parentPtr;
   const struct redblacktree_node* node;
   const struct redblacktree_node* parent;
   int                                           cmpResult = 0;

#ifdef DEBUG
   printf("nearest next: ");
   rbt->print_function(cmpNode, stdout);
   printf("\n");
   rbt_print(bt, stdout);
#endif

   parentPtr = NULL;
   nodePtr   = &rbt->null_node.left_subtree;
   while(*nodePtr != &rbt->null_node) {
      cmpResult = rbt->comparison_function(cmpNode, *nodePtr);
      if(cmpResult < 0) {
         parentPtr = nodePtr;
         nodePtr   = &(*nodePtr)->left_subtree;
      }
      else if(cmpResult > 0) {
         parentPtr = nodePtr;
         nodePtr   = &(*nodePtr)->right_subtree;
      }
      if(cmpResult == 0) {
         return(rbt_get_next(rbt, *nodePtr));
      }
   }

   if(parentPtr == NULL) {
      if(cmpResult < 0) {
         return(rbt->null_node.left_subtree);
      }
      return(NULL);
   }
   else {
      /* The new node would be the left child of its parent.
         => The parent is the nearest next node! */
      if(nodePtr == &(*parentPtr)->left_subtree) {
         return(*parentPtr);
      }
      else {
         parent = *parentPtr;

         /* If there is a right subtree, the nearest next node is the
            leftmost child of the right subtree. */
         if(parent->right_subtree != &rbt->null_node) {
            node = parent->right_subtree;
            while(node->left_subtree != &rbt->null_node) {
               node = node->left_subtree;
            }
            if(node != &rbt->null_node) {
               return((struct redblacktree_node*)node);
            }
         }

         /* If there is no right subtree, the nearest next node is an
            ancestor node which has the node on its left side. */
         else {
            node   = parent;
            parent = node->parent;
            while((parent != &rbt->null_node) && (node == parent->right_subtree)) {
               node   = parent;
               parent = parent->parent;
            }
            if(parent != &rbt->null_node) {
               return((struct redblacktree_node*)parent);
            }
         }
      }
   }
   return(NULL);
}


/* ###### Get number of elements ########################################## */
size_t rbt_get_elements(const struct redblacktree* rbt)
{
   return(rbt->elements);
}


/* ###### Get prev node by walking through the tree (does *not* use list!) */
static struct redblacktree_node* rbt_internal_find_prev(const struct redblacktree*      rbt,
                                                        const struct redblacktree_node* cmpNode)
{
   const struct redblacktree_node* node = cmpNode->left_subtree;
   const struct redblacktree_node* parent;

   if(node != &rbt->null_node) {
      while(node->right_subtree != &rbt->null_node) {
         node = node->right_subtree;
      }
      return((struct redblacktree_node*)node);
   }
   else {
      node   = cmpNode;
      parent = cmpNode->parent;
      while((parent != &rbt->null_node) && (node == parent->left_subtree)) {
         node   = parent;
         parent = parent->parent;
      }
      return((struct redblacktree_node*)parent);
   }
}


/* ###### Get next node by walking through the tree (does *not* use list!) */
static struct redblacktree_node* rbt_internal_find_next(const struct redblacktree*      rbt,
                                                        const struct redblacktree_node* cmpNode)
{
   const struct redblacktree_node* node = cmpNode->right_subtree;
   const struct redblacktree_node* parent;

   if(node != &rbt->null_node) {
      while(node->left_subtree != &rbt->null_node) {
         node = node->left_subtree;
      }
      return((struct redblacktree_node*)node);
   }
   else {
      node   = cmpNode;
      parent = cmpNode->parent;
      while((parent != &rbt->null_node) && (node == parent->right_subtree)) {
         node   = parent;
         parent = parent->parent;
      }
      return((struct redblacktree_node*)parent);
   }
}


/* ###### Find node ####################################################### */
struct redblacktree_node* rbt_find(const struct redblacktree*      rbt,
                                   const struct redblacktree_node* cmpNode)
{
#ifdef DEBUG
   printf("find: ");
   rbt->print_function(cmpNode, stdout);
   printf("\n");
#endif

   struct redblacktree_node* node = rbt->null_node.left_subtree;
   while(node != &rbt->null_node) {
      const int cmpResult = rbt->comparison_function(cmpNode, node);
      if(cmpResult == 0) {
         return(node);
      }
      else if(cmpResult < 0) {
         node = node->left_subtree;
      }
      else {
         node = node->right_subtree;
      }
   }
   return(NULL);
}


/* ###### Get value sum from root node ################################### */
redblacktree_node_value_type rbt_get_value_sum(const struct redblacktree* rbt)
{
   return(rbt->null_node.left_subtree->value_sum);
}


/* ##### Rotation with left subtree ###################################### */
static void rbt_rotate_left(struct redblacktree_node* node)
{
   struct redblacktree_node* lower;
   struct redblacktree_node* lowleft;
   struct redblacktree_node* upparent;

   lower = node->right_subtree;
   node->right_subtree = lowleft = lower->left_subtree;
   lowleft->parent = node;
   lower->parent = upparent = node->parent;

   if(node == upparent->left_subtree) {
      upparent->left_subtree = lower;
   } else {
      assert(node == upparent->right_subtree);
      upparent->right_subtree = lower;
   }

   lower->left_subtree = node;
   node->parent = lower;

   rbt_update_value_sum(node);
   rbt_update_value_sum(node->parent);
}


/* ##### Rotation with ripht subtree ##################################### */
static void rbt_rotate_right(struct redblacktree_node* node)
{
   struct redblacktree_node* lower;
   struct redblacktree_node* lowright;
   struct redblacktree_node* upparent;

   lower = node->left_subtree;
   node->left_subtree = lowright = lower->right_subtree;
   lowright->parent = node;
   lower->parent = upparent = node->parent;

   if(node == upparent->right_subtree) {
      upparent->right_subtree = lower;
   } else {
      assert(node == upparent->left_subtree);
      upparent->left_subtree = lower;
   }

   lower->right_subtree = node;
   node->parent = lower;

   rbt_update_value_sum(node);
   rbt_update_value_sum(node->parent);
}


/* ###### Insert ######################################################### */
struct redblacktree_node* rbt_insert(struct redblacktree*      rbt,
                                     struct redblacktree_node* node)
{
   int                       cmpResult = -1;
   struct redblacktree_node* where     = rbt->null_node.left_subtree;
   struct redblacktree_node* parent    = &rbt->null_node;
   struct redblacktree_node* result;
   struct redblacktree_node* uncle;
   struct redblacktree_node* grandparent;
#ifdef DEBUG
   printf("insert: ");
   rbt->print_function(node, stdout);
   printf("\n");
#endif


   /* ====== Find location of new node =================================== */
   while(where != &rbt->null_node) {
      parent = where;
      cmpResult = rbt->comparison_function(node, where);
      if(cmpResult < 0) {
         where = where->left_subtree;
      }
      else if(cmpResult > 0) {
         where = where->right_subtree;
      }
      else {
         /* Node with same key is already available -> return. */
         result = where;
         goto finished;
      }
   }
   assert(where == &rbt->null_node);

   if(cmpResult < 0) {
      parent->left_subtree = node;
   }
   else {
      parent->right_subtree = node;
   }


   /* ====== Link node =================================================== */
   node->parent        = parent;
   node->left_subtree  = &rbt->null_node;
   node->right_subtree = &rbt->null_node;
   node->value_sum     = node->value;
   rbt->elements++;
   result = node;


   /* ====== Update parent's value sum =================================== */
   rbt_update_value_sums_up_to_root(rbt, node->parent);


   /* ====== Ensure red-black tree properties ============================ */
   node->color = Red;
   while (parent->color == Red) {
      grandparent = parent->parent;
      if(parent == grandparent->left_subtree) {
         uncle = grandparent->right_subtree;
         if(uncle->color == Red) {
            parent->color  = Black;
            uncle->color   = Black;
            grandparent->color = Red;
            node           = grandparent;
            parent         = grandparent->parent;
         } else {
            if(node == parent->right_subtree) {
               rbt_rotate_left(parent);
               parent = node;
               assert(grandparent == parent->parent);
            }
            parent->color  = Black;
            grandparent->color = Red;
            rbt_rotate_right(grandparent);
            break;
         }
      } else {
         uncle = grandparent->left_subtree;
         if(uncle->color == Red) {
            parent->color  = Black;
            uncle->color   = Black;
            grandparent->color = Red;
            node           = grandparent;
            parent         = grandparent->parent;
         } else {
            if(node == parent->left_subtree) {
               rbt_rotate_right(parent);
               parent = node;
               assert(grandparent == parent->parent);
            }
            parent->color  = Black;
            grandparent->color = Red;
            rbt_rotate_left(grandparent);
            break;
         }
      }
   }
   rbt->null_node.left_subtree->color = Black;


finished:
#ifdef DEBUG
   rbt_print(rbt, stdout);
#endif
#ifdef VERIFY
   rbt_verify(rbt);
#endif
   return(result);
}


/* ###### Remove ######################################################### */
struct redblacktree_node* rbt_remove(struct redblacktree*      rbt,
                                     struct redblacktree_node* node)
{
   struct redblacktree_node*          child;
   struct redblacktree_node*          delparent;
   struct redblacktree_node*          parent;
   struct redblacktree_node*          sibling;
   struct redblacktree_node*          next;
   struct redblacktree_node*          nextparent;
   enum redblacktree_node_color_type  nextcolor;
#ifdef DEBUG
   printf("remove: ");
   rbt->print_function(node, stdout);
   printf("\n");
#endif

   assert(rbt_node_is_linked(node));

   /* ====== Unlink node ================================================= */
   if((node->left_subtree != &rbt->null_node) && (node->right_subtree != &rbt->null_node)) {
      next       = rbt_get_next(rbt, node);
      nextparent = next->parent;
      nextcolor  = next->color;

      assert(next != &rbt->null_node);
      assert(next->parent != &rbt->null_node);
      assert(next->left_subtree == &rbt->null_node);

      child         = next->right_subtree;
      child->parent = nextparent;
      if(nextparent->left_subtree == next) {
         nextparent->left_subtree = child;
      } else {
         assert(nextparent->right_subtree == next);
         nextparent->right_subtree = child;
      }


      delparent                  = node->parent;
      next->parent               = delparent;
      next->left_subtree          = node->left_subtree;
      next->right_subtree         = node->right_subtree;
      next->left_subtree->parent  = next;
      next->right_subtree->parent = next;
      next->color                = node->color;
      node->color                = nextcolor;

      if(delparent->left_subtree == node) {
         delparent->left_subtree = next;
      } else {
         assert(delparent->right_subtree == node);
         delparent->right_subtree = next;
      }

      /* ====== Update parent's value sum ================================ */
      rbt_update_value_sums_up_to_root(rbt, next);
      rbt_update_value_sums_up_to_root(rbt, nextparent);
   } else {
      assert(node != &rbt->null_node);
      assert((node->left_subtree == &rbt->null_node) || (node->right_subtree == &rbt->null_node));

      child         = (node->left_subtree != &rbt->null_node) ? node->left_subtree : node->right_subtree;
      child->parent = delparent = node->parent;

      if(node == delparent->left_subtree) {
         delparent->left_subtree = child;
      } else {
         assert(node == delparent->right_subtree);
         delparent->right_subtree = child;
      }

      /* ====== Update parent's value sum ================================ */
      rbt_update_value_sums_up_to_root(rbt, delparent);
   }


   /* ====== Unlink node from list and invalidate pointers =============== */
   node->parent       = NULL;
   node->right_subtree = NULL;
   node->left_subtree  = NULL;
   assert(rbt->elements > 0);
   rbt->elements--;


   /* ====== Ensure red-black properties ================================= */
   if(node->color == Black) {
      rbt->null_node.left_subtree->color = Red;

      while (child->color == Black) {
         parent = child->parent;
         if(child == parent->left_subtree) {
            sibling = parent->right_subtree;
            assert(sibling != &rbt->null_node);
            if(sibling->color == Red) {
               sibling->color = Black;
               parent->color = Red;
               rbt_rotate_left(parent);
               sibling = parent->right_subtree;
               assert(sibling != &rbt->null_node);
            }
            if((sibling->left_subtree->color == Black) &&
               (sibling->right_subtree->color == Black)) {
               sibling->color = Red;
               child = parent;
            } else {
               if(sibling->right_subtree->color == Black) {
                  assert(sibling->left_subtree->color == Red);
                  sibling->left_subtree->color = Black;
                  sibling->color = Red;
                  rbt_rotate_right(sibling);
                  sibling = parent->right_subtree;
                  assert(sibling != &rbt->null_node);
               }
               sibling->color = parent->color;
               sibling->right_subtree->color = Black;
               parent->color = Black;
               rbt_rotate_left(parent);
               break;
            }
         } else {
            assert(child == parent->right_subtree);
            sibling = parent->left_subtree;
            assert(sibling != &rbt->null_node);
            if(sibling->color == Red) {
               sibling->color = Black;
               parent->color = Red;
               rbt_rotate_right(parent);
               sibling = parent->left_subtree;
               assert(sibling != &rbt->null_node);
            }
            if((sibling->right_subtree->color == Black) &&
               (sibling->left_subtree->color == Black)) {
               sibling->color = Red;
               child = parent;
            } else {
               if(sibling->left_subtree->color == Black) {
                  assert(sibling->right_subtree->color == Red);
                  sibling->right_subtree->color = Black;
                  sibling->color = Red;
                  rbt_rotate_left(sibling);
                  sibling = parent->left_subtree;
                  assert(sibling != &rbt->null_node);
               }
               sibling->color = parent->color;
               sibling->left_subtree->color = Black;
               parent->color = Black;
               rbt_rotate_right(parent);
               break;
            }
         }
      }
      child->color = Black;
      rbt->null_node.left_subtree->color = Black;
   }


#ifdef DEBUG
    rbt_print(rbt, stdout);
#endif
#ifdef VERIFY
    rbt_verify(rbt);
#endif
   return(node);
}


/* ##### Get node by value ############################################### */
struct redblacktree_node* rbt_get_node_by_value(const struct redblacktree* rbt,
                                                redblacktree_node_value_type  value)
{
   const struct redblacktree_node* node = rbt->null_node.left_subtree;
   for(;;) {
      if(value < node->left_subtree->value_sum) {
         if(node->left_subtree != &rbt->null_node) {
            node = node->left_subtree;
         }
         else {
            break;
         }
      }
      else if(value < node->left_subtree->value_sum + node->value) {
         break;
      }
      else {
         if(node->right_subtree != &rbt->null_node) {
            value -= node->left_subtree->value_sum + node->value;
            node = node->right_subtree;
         }
         else {
            break;
         }
      }
   }

   if(node !=  &rbt->null_node) {
      return((struct redblacktree_node*)node);
   }
   return(NULL);
}


/* ##### Internal verification function ################################## */
static size_t rbt_internal_verify(struct redblacktree*       rbt,
                                  struct redblacktree_node*  parent,
                                  struct redblacktree_node*  node,
                                  struct redblacktree_node** lastRedBlackTreeNode,
                                  size_t*                    counter)
{
   size_t leftHeight;
   size_t rightHeight;

   if(node != &rbt->null_node) {
      /* ====== Print node =============================================== */
#ifdef DEBUG
      printf("verifying ");
      rbt_print_node(rbt, node, stdout);
      puts("");
#endif

      /* ====== Correct parent? ========================================== */
      assert(node->parent == parent);

      /* ====== Correct tree and heap properties? ======================== */
      if(node->left_subtree != &rbt->null_node) {
         assert(rbt->comparison_function(node, node->left_subtree) > 0);
      }
      if(node->right_subtree != &rbt->null_node) {
         assert(rbt->comparison_function(node, node->right_subtree) < 0);
      }

      /* ====== Is value sum okay? ======================================= */
      assert(node->value_sum == node->left_subtree->value_sum +
                              node->value +
                              node->right_subtree->value_sum);

      /* ====== Is left subtree okay? ==================================== */
      leftHeight = rbt_internal_verify(
                      rbt, node, node->left_subtree, lastRedBlackTreeNode,
                      counter);

      /* ====== Count elements =========================================== */
      (*counter)++;

      /* ====== Is right subtree okay? =================================== */
      rightHeight = rbt_internal_verify(
                       rbt, node, node->right_subtree, lastRedBlackTreeNode,
                       counter);

      /* ====== Verify red-black property ================================ */
      assert((leftHeight != 0) || (rightHeight != 0));
      assert(leftHeight == rightHeight);
      if(node->color == Red) {
         assert(node->left_subtree->color == Black);
         assert(node->right_subtree->color == Black);
         return(leftHeight);
      }
      assert(node->color == Black);
      return(leftHeight + 1);
   }
   return(1);
}


/* ##### Verify structures ############################################### */
void rbt_verify(struct redblacktree* rbt)
{
   size_t                   counter              = 0;
   struct redblacktree_node* lastRedBlackTreeNode = NULL;

   assert(rbt->null_node.color == Black);
   assert(rbt->null_node.value == 0);
   assert(rbt->null_node.value_sum == 0);

   assert(rbt_internal_verify(rbt, &rbt->null_node,
                     rbt->null_node.left_subtree, &lastRedBlackTreeNode,
                     &counter) != 0);
   assert(counter == rbt->elements);
}


#ifdef __cplusplus
}
#endif
