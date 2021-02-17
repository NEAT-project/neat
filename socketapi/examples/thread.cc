/*
 * thread.cc: PThread class
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <iostream>

#include "thread.h"


using namespace std;


Thread::Thread()
{
   MyThread = 0;
}

Thread::~Thread()
{
   if(MyThread != 0) {
      waitForFinish();
   }
}

void* Thread::startRoutine(void* object)
{
   Thread* thread = (Thread*)object;
   thread->run();
   return(NULL);
}

void Thread::start()
{
   if(MyThread == 0) {
      if(pthread_create(&MyThread, NULL, startRoutine, (void*)this) != 0) {
         cerr << "ERROR: Unable to start new thread!" << endl;
         exit(1);
      }
   }
   else {
      cerr << "ERROR: Thread already running!" << endl;
   }
}

void Thread::waitForFinish()
{
   if(MyThread != 0) {
      pthread_join(MyThread, NULL);
      MyThread = 0;
   }
}

void Thread::delay(const unsigned int us)
{
   usleep(us);
}
