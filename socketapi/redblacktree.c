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
   node->Parent       = NULL;
   node->LeftSubtree  = NULL;
   node->RightSubtree = NULL;
   node->Color        = Black;
   node->Value        = 0;
   node->ValueSum     = 0;
}


/* ###### Invalidate ##################################################### */
void rbt_node_delete(struct redblacktree_node* node)
{
   node->Parent       = NULL;
   node->LeftSubtree  = NULL;
   node->RightSubtree = NULL;
   node->Color        = Black;
   node->Value        = 0;
   node->ValueSum     = 0;
}


/* ###### Is node linked? ################################################ */
int rbt_node_is_linked(const struct redblacktree_node* node)
{
   return(node->LeftSubtree != NULL);
}


/* ##### Initialize ###################################################### */
void rbt_new(struct redblacktree* rbt,
             void                 (*printFunction)(const void* node, FILE* fd),
             int                  (*comparisonFunction)(const void* node1, const void* node2))
{
   rbt->PrintFunction         = printFunction;
   rbt->ComparisonFunction    = comparisonFunction;
   rbt->NullNode.Parent       = &rbt->NullNode;
   rbt->NullNode.LeftSubtree  = &rbt->NullNode;
   rbt->NullNode.RightSubtree = &rbt->NullNode;
   rbt->NullNode.Color        = Black;
   rbt->NullNode.Value        = 0;
   rbt->NullNode.ValueSum     = 0;
   rbt->Elements              = 0;
}


/* ##### Invalidate ###################################################### */
void rbt_delete(struct redblacktree* rbt)
{
   rbt->Elements              = 0;
   rbt->NullNode.Parent       = NULL;
   rbt->NullNode.LeftSubtree  = NULL;
   rbt->NullNode.RightSubtree = NULL;
}


/* ##### Update value sum ################################################ */
inline static void rbt_update_value_sum(struct redblacktree_node* node)
{
   node->ValueSum = node->LeftSubtree->ValueSum + node->Value + node->RightSubtree->ValueSum;
}


/* ##### Update value sum for node and all parents up to tree root ####### */
static void rbt_update_value_sums_up_to_root(struct redblacktree*      rbt,
                                             struct redblacktree_node* node)
{
   while(node != &rbt->NullNode) {
       rbt_update_value_sum(node);
       node = node->Parent;
   }
}


/* ###### Internal method for printing a node ############################ */
static void rbt_print_node(const struct redblacktree*      rbt,
                           const struct redblacktree_node* node,
                           FILE*                           fd)
{
   rbt->PrintFunction(node, fd);
#ifdef DEBUG
   fprintf(fd, " ptr=%p c=%s v=%llu vsum=%llu",
           node, ((node->Color == Red) ? "Red" : "Black"),
           node->Value, node->ValueSum);
   if(node->LeftSubtree != &rbt->NullNode) {
      fprintf(fd, " l=%p[", node->LeftSubtree);
      rbt->PrintFunction(node->LeftSubtree, fd);
      fprintf(fd, "]");
   }
   else {
      fprintf(fd, " l=()");
   }
   if(node->RightSubtree != &rbt->NullNode) {
      fprintf(fd, " r=%p[", node->RightSubtree);
      rbt->PrintFunction(node->RightSubtree, fd);
      fprintf(fd, "]");
   }
   else {
      fprintf(fd, " r=()");
   }
   if(node->Parent != &rbt->NullNode) {
      fprintf(fd, " p=%p[", node->Parent);
      rbt->PrintFunction(node->Parent, fd);
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
   if(node != &rbt->NullNode) {
      rbt_internal_print(rbt, node->LeftSubtree, fd);
      rbt_print_node(rbt, node, fd);
      rbt_internal_print(rbt, node->RightSubtree, fd);
   }
}


/* ###### Print tree ##################################################### */
void rbt_print(const struct redblacktree* rbt,
               FILE*                      fd)
{
#ifdef DEBUG
   fprintf(fd, "\n\nroot=%p[", rbt->NullNode.LeftSubtree);
   if(rbt->NullNode.LeftSubtree != &rbt->NullNode) {
      rbt->PrintFunction(rbt->NullNode.LeftSubtree, fd);
   }
   fprintf(fd, "] null=%p   \n", &rbt->NullNode);
#endif
   rbt_internal_print(rbt, rbt->NullNode.LeftSubtree, fd);
   fputs("\n", fd);
}


/* ###### Is tree empty? ################################################# */
int rbt_is_empty(const struct redblacktree* rbt)
{
   return(rbt->NullNode.LeftSubtree == &rbt->NullNode);
}


/* ###### Get first node ################################################## */
struct redblacktree_node* rbt_get_first(const struct redblacktree* rbt)
{
   const struct redblacktree_node* node = rbt->NullNode.LeftSubtree;
   if(node == &rbt->NullNode) {
      node = rbt->NullNode.RightSubtree;
   }
   while(node->LeftSubtree != &rbt->NullNode) {
      node = node->LeftSubtree;
   }
   if(node != &rbt->NullNode) {
      return((struct redblacktree_node*)node);
   }
   return(NULL);
}


/* ###### Get last node ################################################### */
struct redblacktree_node* rbt_get_last(const struct redblacktree* rbt)
{
   const struct redblacktree_node* node = rbt->NullNode.RightSubtree;
   if(node == &rbt->NullNode) {
      node = rbt->NullNode.LeftSubtree;
   }
   while(node->RightSubtree != &rbt->NullNode) {
      node = node->RightSubtree;
   }
   if(node != &rbt->NullNode) {
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
   if(result != &rbt->NullNode) {
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
   if(result != &rbt->NullNode) {
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
   rbt->PrintFunction(cmpNode, stdout);
   printf("\n");
   rbt_print(rbt, stdout);
#endif

   parentPtr = NULL;
   nodePtr   = &rbt->NullNode.LeftSubtree;
   while(*nodePtr != &rbt->NullNode) {
      cmpResult = rbt->ComparisonFunction(cmpNode, *nodePtr);
      if(cmpResult < 0) {
         parentPtr = nodePtr;
         nodePtr   = &(*nodePtr)->LeftSubtree;
      }
      else if(cmpResult > 0) {
         parentPtr = nodePtr;
         nodePtr   = &(*nodePtr)->RightSubtree;
      }
      if(cmpResult == 0) {
         return(rbt_get_prev(rbt, *nodePtr));
      }
   }

   if(parentPtr == NULL) {
      if(cmpResult > 0) {
         return(rbt->NullNode.LeftSubtree);
      }
      return(NULL);
   }
   else {
      /* The new node would be the right child of its parent.
         => The parent is the nearest previous node! */
      if(nodePtr == &(*parentPtr)->RightSubtree) {
         return(*parentPtr);
      }
      else {
         parent = *parentPtr;

         /* If there is a left subtree, the nearest previous node is the
            rightmost child of the left subtree. */
         if(parent->LeftSubtree != &rbt->NullNode) {
            node = parent->LeftSubtree;
            while(node->RightSubtree != &rbt->NullNode) {
               node = node->RightSubtree;
            }
            if(node != &rbt->NullNode) {
               return((struct redblacktree_node*)node);
            }
         }

         /* If there is no left subtree, the nearest previous node is an
            ancestor node which has the node on its right side. */
         else {
            node   = parent;
            parent = node->Parent;
            while((parent != &rbt->NullNode) && (node == parent->LeftSubtree)) {
               node   = parent;
               parent = parent->Parent;
            }
            if(parent != &rbt->NullNode) {
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
   rbt->PrintFunction(cmpNode, stdout);
   printf("\n");
   rbt_print(bt, stdout);
#endif

   parentPtr = NULL;
   nodePtr   = &rbt->NullNode.LeftSubtree;
   while(*nodePtr != &rbt->NullNode) {
      cmpResult = rbt->ComparisonFunction(cmpNode, *nodePtr);
      if(cmpResult < 0) {
         parentPtr = nodePtr;
         nodePtr   = &(*nodePtr)->LeftSubtree;
      }
      else if(cmpResult > 0) {
         parentPtr = nodePtr;
         nodePtr   = &(*nodePtr)->RightSubtree;
      }
      if(cmpResult == 0) {
         return(rbt_get_next(rbt, *nodePtr));
      }
   }

   if(parentPtr == NULL) {
      if(cmpResult < 0) {
         return(rbt->NullNode.LeftSubtree);
      }
      return(NULL);
   }
   else {
      /* The new node would be the left child of its parent.
         => The parent is the nearest next node! */
      if(nodePtr == &(*parentPtr)->LeftSubtree) {
         return(*parentPtr);
      }
      else {
         parent = *parentPtr;

         /* If there is a right subtree, the nearest next node is the
            leftmost child of the right subtree. */
         if(parent->RightSubtree != &rbt->NullNode) {
            node = parent->RightSubtree;
            while(node->LeftSubtree != &rbt->NullNode) {
               node = node->LeftSubtree;
            }
            if(node != &rbt->NullNode) {
               return((struct redblacktree_node*)node);
            }
         }

         /* If there is no right subtree, the nearest next node is an
            ancestor node which has the node on its left side. */
         else {
            node   = parent;
            parent = node->Parent;
            while((parent != &rbt->NullNode) && (node == parent->RightSubtree)) {
               node   = parent;
               parent = parent->Parent;
            }
            if(parent != &rbt->NullNode) {
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
   return(rbt->Elements);
}


/* ###### Get prev node by walking through the tree (does *not* use list!) */
static struct redblacktree_node* rbt_internal_find_prev(const struct redblacktree*      rbt,
                                                        const struct redblacktree_node* cmpNode)
{
   const struct redblacktree_node* node = cmpNode->LeftSubtree;
   const struct redblacktree_node* parent;

   if(node != &rbt->NullNode) {
      while(node->RightSubtree != &rbt->NullNode) {
         node = node->RightSubtree;
      }
      return((struct redblacktree_node*)node);
   }
   else {
      node   = cmpNode;
      parent = cmpNode->Parent;
      while((parent != &rbt->NullNode) && (node == parent->LeftSubtree)) {
         node   = parent;
         parent = parent->Parent;
      }
      return((struct redblacktree_node*)parent);
   }
}


/* ###### Get next node by walking through the tree (does *not* use list!) */
static struct redblacktree_node* rbt_internal_find_next(const struct redblacktree*      rbt,
                                                        const struct redblacktree_node* cmpNode)
{
   const struct redblacktree_node* node = cmpNode->RightSubtree;
   const struct redblacktree_node* parent;

   if(node != &rbt->NullNode) {
      while(node->LeftSubtree != &rbt->NullNode) {
         node = node->LeftSubtree;
      }
      return((struct redblacktree_node*)node);
   }
   else {
      node   = cmpNode;
      parent = cmpNode->Parent;
      while((parent != &rbt->NullNode) && (node == parent->RightSubtree)) {
         node   = parent;
         parent = parent->Parent;
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
   rbt->PrintFunction(cmpNode, stdout);
   printf("\n");
#endif

   struct redblacktree_node* node = rbt->NullNode.LeftSubtree;
   while(node != &rbt->NullNode) {
      const int cmpResult = rbt->ComparisonFunction(cmpNode, node);
      if(cmpResult == 0) {
         return(node);
      }
      else if(cmpResult < 0) {
         node = node->LeftSubtree;
      }
      else {
         node = node->RightSubtree;
      }
   }
   return(NULL);
}


/* ###### Get value sum from root node ################################### */
redblacktree_node_value_type rbt_get_value_sum(const struct redblacktree* rbt)
{
   return(rbt->NullNode.LeftSubtree->ValueSum);
}


/* ##### Rotation with left subtree ###################################### */
static void rbt_rotate_left(struct redblacktree_node* node)
{
   struct redblacktree_node* lower;
   struct redblacktree_node* lowleft;
   struct redblacktree_node* upparent;

   lower = node->RightSubtree;
   node->RightSubtree = lowleft = lower->LeftSubtree;
   lowleft->Parent = node;
   lower->Parent = upparent = node->Parent;

   if(node == upparent->LeftSubtree) {
      upparent->LeftSubtree = lower;
   } else {
      assert(node == upparent->RightSubtree);
      upparent->RightSubtree = lower;
   }

   lower->LeftSubtree = node;
   node->Parent = lower;

   rbt_update_value_sum(node);
   rbt_update_value_sum(node->Parent);
}


/* ##### Rotation with ripht subtree ##################################### */
static void rbt_rotate_right(struct redblacktree_node* node)
{
   struct redblacktree_node* lower;
   struct redblacktree_node* lowright;
   struct redblacktree_node* upparent;

   lower = node->LeftSubtree;
   node->LeftSubtree = lowright = lower->RightSubtree;
   lowright->Parent = node;
   lower->Parent = upparent = node->Parent;

   if(node == upparent->RightSubtree) {
      upparent->RightSubtree = lower;
   } else {
      assert(node == upparent->LeftSubtree);
      upparent->LeftSubtree = lower;
   }

   lower->RightSubtree = node;
   node->Parent = lower;

   rbt_update_value_sum(node);
   rbt_update_value_sum(node->Parent);
}


/* ###### Insert ######################################################### */
struct redblacktree_node* rbt_insert(struct redblacktree*      rbt,
                                     struct redblacktree_node* node)
{
   int                       cmpResult = -1;
   struct redblacktree_node* where     = rbt->NullNode.LeftSubtree;
   struct redblacktree_node* parent    = &rbt->NullNode;
   struct redblacktree_node* result;
   struct redblacktree_node* uncle;
   struct redblacktree_node* grandparent;
#ifdef DEBUG
   printf("insert: ");
   rbt->PrintFunction(node, stdout);
   printf("\n");
#endif


   /* ====== Find location of new node =================================== */
   while(where != &rbt->NullNode) {
      parent = where;
      cmpResult = rbt->ComparisonFunction(node, where);
      if(cmpResult < 0) {
         where = where->LeftSubtree;
      }
      else if(cmpResult > 0) {
         where = where->RightSubtree;
      }
      else {
         /* Node with same key is already available -> return. */
         result = where;
         goto finished;
      }
   }
   assert(where == &rbt->NullNode);

   if(cmpResult < 0) {
      parent->LeftSubtree = node;
   }
   else {
      parent->RightSubtree = node;
   }


   /* ====== Link node =================================================== */
   node->Parent       = parent;
   node->LeftSubtree  = &rbt->NullNode;
   node->RightSubtree = &rbt->NullNode;
   node->ValueSum     = node->Value;
   rbt->Elements++;
   result = node;


   /* ====== Update parent's value sum =================================== */
   rbt_update_value_sums_up_to_root(rbt, node->Parent);


   /* ====== Ensure red-black tree properties ============================ */
   node->Color = Red;
   while (parent->Color == Red) {
      grandparent = parent->Parent;
      if(parent == grandparent->LeftSubtree) {
         uncle = grandparent->RightSubtree;
         if(uncle->Color == Red) {
            parent->Color  = Black;
            uncle->Color   = Black;
            grandparent->Color = Red;
            node           = grandparent;
            parent         = grandparent->Parent;
         } else {
            if(node == parent->RightSubtree) {
               rbt_rotate_left(parent);
               parent = node;
               assert(grandparent == parent->Parent);
            }
            parent->Color  = Black;
            grandparent->Color = Red;
            rbt_rotate_right(grandparent);
            break;
         }
      } else {
         uncle = grandparent->LeftSubtree;
         if(uncle->Color == Red) {
            parent->Color  = Black;
            uncle->Color   = Black;
            grandparent->Color = Red;
            node           = grandparent;
            parent         = grandparent->Parent;
         } else {
            if(node == parent->LeftSubtree) {
               rbt_rotate_right(parent);
               parent = node;
               assert(grandparent == parent->Parent);
            }
            parent->Color  = Black;
            grandparent->Color = Red;
            rbt_rotate_left(grandparent);
            break;
         }
      }
   }
   rbt->NullNode.LeftSubtree->Color = Black;


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
   struct redblacktree_node*          delParent;
   struct redblacktree_node*          parent;
   struct redblacktree_node*          sibling;
   struct redblacktree_node*          next;
   struct redblacktree_node*          nextParent;
   enum redblacktree_node_color_type  nextColor;
#ifdef DEBUG
   printf("remove: ");
   rbt->PrintFunction(node, stdout);
   printf("\n");
#endif

   assert(rbt_node_is_linked(node));

   /* ====== Unlink node ================================================= */
   if((node->LeftSubtree != &rbt->NullNode) && (node->RightSubtree != &rbt->NullNode)) {
      next       = rbt_get_next(rbt, node);
      nextParent = next->Parent;
      nextColor  = next->Color;

      assert(next != &rbt->NullNode);
      assert(next->Parent != &rbt->NullNode);
      assert(next->LeftSubtree == &rbt->NullNode);

      child         = next->RightSubtree;
      child->Parent = nextParent;
      if(nextParent->LeftSubtree == next) {
         nextParent->LeftSubtree = child;
      } else {
         assert(nextParent->RightSubtree == next);
         nextParent->RightSubtree = child;
      }


      delParent                  = node->Parent;
      next->Parent               = delParent;
      next->LeftSubtree          = node->LeftSubtree;
      next->RightSubtree         = node->RightSubtree;
      next->LeftSubtree->Parent  = next;
      next->RightSubtree->Parent = next;
      next->Color                = node->Color;
      node->Color                = nextColor;

      if(delParent->LeftSubtree == node) {
         delParent->LeftSubtree = next;
      } else {
         assert(delParent->RightSubtree == node);
         delParent->RightSubtree = next;
      }

      /* ====== Update parent's value sum ================================ */
      rbt_update_value_sums_up_to_root(rbt, next);
      rbt_update_value_sums_up_to_root(rbt, nextParent);
   } else {
      assert(node != &rbt->NullNode);
      assert((node->LeftSubtree == &rbt->NullNode) || (node->RightSubtree == &rbt->NullNode));

      child         = (node->LeftSubtree != &rbt->NullNode) ? node->LeftSubtree : node->RightSubtree;
      child->Parent = delParent = node->Parent;

      if(node == delParent->LeftSubtree) {
         delParent->LeftSubtree = child;
      } else {
         assert(node == delParent->RightSubtree);
         delParent->RightSubtree = child;
      }

      /* ====== Update parent's value sum ================================ */
      rbt_update_value_sums_up_to_root(rbt, delParent);
   }


   /* ====== Unlink node from list and invalidate pointers =============== */
   node->Parent       = NULL;
   node->RightSubtree = NULL;
   node->LeftSubtree  = NULL;
   assert(rbt->Elements > 0);
   rbt->Elements--;


   /* ====== Ensure red-black properties ================================= */
   if(node->Color == Black) {
      rbt->NullNode.LeftSubtree->Color = Red;

      while (child->Color == Black) {
         parent = child->Parent;
         if(child == parent->LeftSubtree) {
            sibling = parent->RightSubtree;
            assert(sibling != &rbt->NullNode);
            if(sibling->Color == Red) {
               sibling->Color = Black;
               parent->Color = Red;
               rbt_rotate_left(parent);
               sibling = parent->RightSubtree;
               assert(sibling != &rbt->NullNode);
            }
            if((sibling->LeftSubtree->Color == Black) &&
               (sibling->RightSubtree->Color == Black)) {
               sibling->Color = Red;
               child = parent;
            } else {
               if(sibling->RightSubtree->Color == Black) {
                  assert(sibling->LeftSubtree->Color == Red);
                  sibling->LeftSubtree->Color = Black;
                  sibling->Color = Red;
                  rbt_rotate_right(sibling);
                  sibling = parent->RightSubtree;
                  assert(sibling != &rbt->NullNode);
               }
               sibling->Color = parent->Color;
               sibling->RightSubtree->Color = Black;
               parent->Color = Black;
               rbt_rotate_left(parent);
               break;
            }
         } else {
            assert(child == parent->RightSubtree);
            sibling = parent->LeftSubtree;
            assert(sibling != &rbt->NullNode);
            if(sibling->Color == Red) {
               sibling->Color = Black;
               parent->Color = Red;
               rbt_rotate_right(parent);
               sibling = parent->LeftSubtree;
               assert(sibling != &rbt->NullNode);
            }
            if((sibling->RightSubtree->Color == Black) &&
               (sibling->LeftSubtree->Color == Black)) {
               sibling->Color = Red;
               child = parent;
            } else {
               if(sibling->LeftSubtree->Color == Black) {
                  assert(sibling->RightSubtree->Color == Red);
                  sibling->RightSubtree->Color = Black;
                  sibling->Color = Red;
                  rbt_rotate_left(sibling);
                  sibling = parent->LeftSubtree;
                  assert(sibling != &rbt->NullNode);
               }
               sibling->Color = parent->Color;
               sibling->LeftSubtree->Color = Black;
               parent->Color = Black;
               rbt_rotate_right(parent);
               break;
            }
         }
      }
      child->Color = Black;
      rbt->NullNode.LeftSubtree->Color = Black;
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
   const struct redblacktree_node* node = rbt->NullNode.LeftSubtree;
   for(;;) {
      if(value < node->LeftSubtree->ValueSum) {
         if(node->LeftSubtree != &rbt->NullNode) {
            node = node->LeftSubtree;
         }
         else {
            break;
         }
      }
      else if(value < node->LeftSubtree->ValueSum + node->Value) {
         break;
      }
      else {
         if(node->RightSubtree != &rbt->NullNode) {
            value -= node->LeftSubtree->ValueSum + node->Value;
            node = node->RightSubtree;
         }
         else {
            break;
         }
      }
   }

   if(node !=  &rbt->NullNode) {
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

   if(node != &rbt->NullNode) {
      /* ====== Print node =============================================== */
#ifdef DEBUG
      printf("verifying ");
      rbt_print_node(rbt, node, stdout);
      puts("");
#endif

      /* ====== Correct parent? ========================================== */
      assert(node->Parent == parent);

      /* ====== Correct tree and heap properties? ======================== */
      if(node->LeftSubtree != &rbt->NullNode) {
         assert(rbt->ComparisonFunction(node, node->LeftSubtree) > 0);
      }
      if(node->RightSubtree != &rbt->NullNode) {
         assert(rbt->ComparisonFunction(node, node->RightSubtree) < 0);
      }

      /* ====== Is value sum okay? ======================================= */
      assert(node->ValueSum == node->LeftSubtree->ValueSum +
                              node->Value +
                              node->RightSubtree->ValueSum);

      /* ====== Is left subtree okay? ==================================== */
      leftHeight = rbt_internal_verify(
                      rbt, node, node->LeftSubtree, lastRedBlackTreeNode,
                      counter);

      /* ====== Count elements =========================================== */
      (*counter)++;

      /* ====== Is right subtree okay? =================================== */
      rightHeight = rbt_internal_verify(
                       rbt, node, node->RightSubtree, lastRedBlackTreeNode,
                       counter);

      /* ====== Verify red-black property ================================ */
      assert((leftHeight != 0) || (rightHeight != 0));
      assert(leftHeight == rightHeight);
      if(node->Color == Red) {
         assert(node->LeftSubtree->Color == Black);
         assert(node->RightSubtree->Color == Black);
         return(leftHeight);
      }
      assert(node->Color == Black);
      return(leftHeight + 1);
   }
   return(1);
}


/* ##### Verify structures ############################################### */
void rbt_verify(struct redblacktree* rbt)
{
   size_t                   counter              = 0;
   struct redblacktree_node* lastRedBlackTreeNode = NULL;

   assert(rbt->NullNode.Color == Black);
   assert(rbt->NullNode.Value == 0);
   assert(rbt->NullNode.ValueSum == 0);

   assert(rbt_internal_verify(rbt, &rbt->NullNode,
                     rbt->NullNode.LeftSubtree, &lastRedBlackTreeNode,
                     &counter) != 0);
   assert(counter == rbt->Elements);
}


#ifdef __cplusplus
}
#endif
