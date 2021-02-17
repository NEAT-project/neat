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

#ifndef IDENTIFIERBITMAP_H
#define IDENTIFIERBITMAP_H

#include <stddef.h>


struct identifier_bitmap
{
   size_t        entries;
   size_t        available;
   size_t        slots;
   unsigned long bitmap[];
};

#define identifier_bitmap_slotsize (sizeof(unsigned long) * 8)


#ifdef __cplusplus
extern "C" {
#endif

struct identifier_bitmap* ibm_new(const size_t entries);
void ibm_delete(struct identifier_bitmap* identifierBitmap);
int ibm_allocate_id(struct identifier_bitmap* identifierBitmap);
int ibm_allocate_specific_id(struct identifier_bitmap* identifierBitmap,
                             const int                id);
void ibm_free_id(struct identifier_bitmap* identifierBitmap, const int id);

#ifdef __cplusplus
}
#endif

#endif
