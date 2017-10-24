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

#include "neat-socketapi-internals.h"

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/ioctl.h>


/* ###### NEAT open() implementation ##################################### */
int nsa_open(const char* pathname, int flags, mode_t mode)
{
   if(nsa_initialize() != NULL) {
      const int fd = open(pathname, flags, mode);
      if(fd >= 0) {
         pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);

         int       result;
         const int newFD = nsa_socket_internal(0, 0, 0, fd, NULL, -1);
         if(newFD >= 0) {
            result = newFD;
         }
         else {
            errno = ENOMEM;
            close(fd);
            result = -1;
         }

         pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
         return(result);
      }
   }
   else {
      errno = ENXIO;
   }
   return(-1);
}


/* ###### NEAT creat() implementation #################################### */
int nsa_creat(const char* pathname, mode_t mode)
{
   if(nsa_initialize() != NULL) {
      const int fd = creat(pathname, mode);
      if(fd >= 0) {
         pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);

         int       result;
         const int newFD = nsa_socket_internal(0, 0, 0, fd, NULL, -1);
         if(newFD >= 0) {
            result = newFD;
         }
         else {
            errno = ENOMEM;
            close(fd);
            result = -1;
         }

         pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
         return(result);
      }
   }
   else {
      errno = ENXIO;
   }
   return(-1);
}


/* ###### NEAT lseek() implementation #################################### */
off_t nsa_lseek(int fd, off_t offset, int whence)
{
   GET_NEAT_SOCKET(fd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      return(lseek(neatSocket->ns_socket_sd, offset, whence));
   }
}


#ifdef _LARGEFILE64_SOURCE
/* ###### NEAT lseek64() implementation ################################## */
off64_t nsa_lseek64(int fd, off64_t offset, int whence)
{
   GET_NEAT_SOCKET(fd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      return(lseek64(neatSocket->ns_socket_sd, offset, whence));
   }
}
#endif


/* ###### NEAT ftruncate() implementation ################################ */
int nsa_ftruncate(int fd, off_t length)
{
   GET_NEAT_SOCKET(fd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      return(ftruncate(neatSocket->ns_socket_sd, length));
   }
}


#ifdef _LARGEFILE64_SOURCE
/* ###### NEAT ftruncate64() implementation ############################## */
int nsa_ftruncate64(int fd, off64_t length)
{
   GET_NEAT_SOCKET(fd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      return(ftruncate64(neatSocket->ns_socket_sd, length));
   }
}
#endif


/* ###### NEAT ioctl() implementation #################################### */
int nsa_ioctl(int fd, int request, const void* argp)
{
   GET_NEAT_SOCKET(fd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      return(ioctl(neatSocket->ns_socket_sd, fd, request, argp));
   }
}


/* ###### NEAT pipe() implementation ##################################### */
int nsa_pipe(int fds[2])
{
   if(nsa_initialize() != NULL) {
      int sysFDs[2];
      if(pipe((int*)&sysFDs) == 0) {
         pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
         fds[0] = nsa_socket_internal(0, 0, 0, sysFDs[0], NULL, -1);
         if(fds[0] >= 0) {
            fds[1] = nsa_socket_internal(0, 0, 0, sysFDs[1], NULL, -1);
            if(fds[1] >= 0) {
               pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
               return(0);
            }
            nsa_close(fds[0]);
            fds[0] = -1;
         }
         errno = ENOMEM;
         close(sysFDs[0]);
         close(sysFDs[1]);
         pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
      }
   }
   else {
      errno = ENXIO;
   }
   return(-1);
}
