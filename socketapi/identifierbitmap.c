/*
 * Socket API implementation for NEAT
 * Copyright (C) 2016-2023 by Thomas Dreibholz <dreibh@simula.no>
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

#include "identifierbitmap.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>


/* ###### Constructor #################################################### */
struct identifier_bitmap* ibm_new(const size_t entries)
{
   const size_t slots = (entries + (identifier_bitmap_slotsize - (entries % identifier_bitmap_slotsize))) /
                           identifier_bitmap_slotsize;
   struct identifier_bitmap* identifierBitmap = (struct identifier_bitmap*)malloc(sizeof(struct identifier_bitmap) + (slots + 1) * sizeof(size_t));
   if(identifierBitmap) {
      memset(&identifierBitmap->bitmap, 0, (slots + 1) * sizeof(size_t));
      identifierBitmap->entries   = entries;
      identifierBitmap->available = entries;
      identifierBitmap->slots     = slots;
   }
   return(identifierBitmap);
}


/* ###### Destructor ##################################################### */
void ibm_delete(struct identifier_bitmap* identifierBitmap)
{
   identifierBitmap->entries = 0;
   free(identifierBitmap);
}


/* ###### Allocate ID #################################################### */
int ibm_allocate_id(struct identifier_bitmap* identifierBitmap)
{
   unsigned int i, j;
   int      id = -1;

   if(identifierBitmap->available > 0) {
      i = 0;
      while(identifierBitmap->bitmap[i] == ~((size_t)0)) {
         i++;
      }
      id = i * identifier_bitmap_slotsize;

      j = 0;
      while((j < identifier_bitmap_slotsize) &&
            (id < (int)identifierBitmap->entries) &&
            (identifierBitmap->bitmap[i] & (1UL << j))) {
         j++;
         id++;
      }
      assert(id < (int)identifierBitmap->entries);

      identifierBitmap->bitmap[i] |= (1UL << j);
      identifierBitmap->available--;
   }

   return(id);
}


/* ###### Allocate specific ID ########################################### */
int ibm_allocate_specific_id(struct identifier_bitmap* identifierBitmap,
                             const int                 id)
{
   unsigned int i, j;

   assert((id >= 0) && (id < (int)identifierBitmap->entries));
   i = id / identifier_bitmap_slotsize;
   j = id % identifier_bitmap_slotsize;
   if(identifierBitmap->bitmap[i] & (1UL << j)) {
      return(-1);
   }
   identifierBitmap->bitmap[i] |= (1UL << j);
   identifierBitmap->available--;
   return(id);
}


/* ###### Free ID ######################################################## */
void ibm_free_id(struct identifier_bitmap* identifierBitmap, const int id)
{
   unsigned int i, j;

   assert((id >= 0) && (id < (int)identifierBitmap->entries));
   i = id / identifier_bitmap_slotsize;
   j = id % identifier_bitmap_slotsize;
   assert(identifierBitmap->bitmap[i] & (1UL << j));
   identifierBitmap->bitmap[i] &= ~(1UL << j);
   identifierBitmap->available++;
}
