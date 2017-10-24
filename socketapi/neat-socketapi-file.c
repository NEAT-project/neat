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
#define __USE_GNU
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/file.h>


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


/* ###### NEAT fchown() implementation ################################### */
int nsa_fchown(int fd, uid_t owner, gid_t group)
{
   GET_NEAT_SOCKET(fd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      return(fchown(neatSocket->ns_socket_sd, owner, group));
   }
}


/* ###### NEAT fsync() implementation #################################### */
int nsa_fsync(int fd)
{
   GET_NEAT_SOCKET(fd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      return(fsync(neatSocket->ns_socket_sd));
   }
}


/* ###### NEAT fdatasync() implementation ################################ */
int nsa_fdatasync(int fd)
{
   GET_NEAT_SOCKET(fd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      return(fdatasync(neatSocket->ns_socket_sd));
   }
}


/* ###### NEAT syncfs() implementation ################################### */
int nsa_syncfs(int fd)
{
   GET_NEAT_SOCKET(fd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      return(syncfs(neatSocket->ns_socket_sd));
   }
}


/* ###### NEAT lockf() implementation #################################### */
int nsa_lockf(int fd, int cmd, off_t len)
{
   GET_NEAT_SOCKET(fd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      return(lockf(neatSocket->ns_socket_sd, cmd, len));
   }
}


/* ###### NEAT flock() implementation #################################### */
int nsa_flock(int fd, int operation)
{
   GET_NEAT_SOCKET(fd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      return(flock(neatSocket->ns_socket_sd, operation));
   }
}


/* ###### NEAT fstat() implementation #################################### */
int nsa_fstat(int fd, struct stat* buf)
{
   GET_NEAT_SOCKET(fd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      return(fstat(neatSocket->ns_socket_sd, buf));
   }
}


/* ###### NEAT fpathconf() implementation ################################ */
long nsa_fpathconf(int fd, int name)
{
   GET_NEAT_SOCKET(fd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      return(fpathconf(neatSocket->ns_socket_sd, name));
   }
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


/* ###### NEAT dup() implementation ###################################### */
int nsa_dup(int oldfd)
{
   GET_NEAT_SOCKET(oldfd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      int fd = dup(neatSocket->ns_socket_sd);
      if(fd >= 0) {
         pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
         const int result = nsa_socket_internal(0, 0, 0, fd, NULL, -1);
         pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
         if(result >= 0) {
            return(result);
         }
         close(fd);
      }
      return(-1);
   }
}


/* ###### NEAT dup2() implementation ##################################### */
int nsa_dup2(int oldfd, int newfd)
{
   GET_NEAT_SOCKET(oldfd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      if(oldfd == newfd) {
         errno = EOPNOTSUPP;
         return(-1);
      }
      int fd = dup(neatSocket->ns_socket_sd);
      if(fd >= 0) {
         pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
         nsa_close(newfd);   // Close exitising file descriptor, if existing.
         const int result = nsa_socket_internal(0, 0, 0, fd, NULL, newfd);
         pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
         if(result >= 0) {
            return(result);
         }
         close(fd);
      }
      return(-1);
   }
}


/* ###### NEAT dup3() implementation ##################################### */
int nsa_dup3(int oldfd, int newfd, int flags)
{
   GET_NEAT_SOCKET(oldfd)
   if(neatSocket->ns_flow != NULL) {
      errno = EOPNOTSUPP;
      return(-1);
   }
   else {
      int fd = dup(neatSocket->ns_socket_sd);
      if(fd >= 0) {
         if(oldfd == newfd) {
            errno = EOPNOTSUPP;
            return(-1);
         }
         pthread_mutex_lock(&gSocketAPIInternals->nsi_socket_set_mutex);
         nsa_close(newfd);   // Close exitising file descriptor, if existing.
         const int result = nsa_socket_internal(0, 0, 0, fd, NULL, newfd);
         pthread_mutex_unlock(&gSocketAPIInternals->nsi_socket_set_mutex);
         if(result >= 0) {
            return(result);
         }
         close(fd);
      }
      return(-1);
   }
}
