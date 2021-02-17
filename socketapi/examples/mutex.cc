/*
 * mutex.cc: PThread mutex class
 *
 * Copyright (C) 2003-2021 by Thomas Dreibholz
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Contact: dreibh@iem.uni-due.de
 */

#include <unistd.h>
#include <pthread.h>

#include "mutex.h"


Mutex::Mutex()
{
   pthread_mutexattr_t attr;
   pthread_mutexattr_init(&attr);
   pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

   pthread_mutex_init(&MyMutex, &attr);

   pthread_mutexattr_destroy(&attr);
}


Mutex::~Mutex()
{
   pthread_mutex_destroy(&MyMutex);
}
