/*
 * httpserver2-threads.cc: Multithreaded HTTP server example
 *
 * Copyright (C) 2003-2023 by Thomas Dreibholz
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
 * Contact: thomas.dreibholz@gmail.com
 */

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <neat-socketapi.h>

#include "thread.h"
#include "ansistyle.h"
#include "safeprint.h"


static const char* properties = "{\
   \"transport\": {\
      \"value\": [ \"MPTCP\", \"SCTP\", \"SCTP/UDP\", \"TCP\" ],\
      \"precedence\": 1\
   }\
}";


class ServiceThread : public Thread
{
   public:
   ServiceThread(int sd);
   ~ServiceThread();

   inline bool hasFinished() {
      return(SocketDesc < 0);
   }

   private:
   void run();

   unsigned int ID;
   int          SocketDesc;
};


ServiceThread::ServiceThread(int sd)
{
   static unsigned int IDCounter = 0;
   ID         = ++IDCounter;
   SocketDesc = sd;
   std::cout << "Starting thread " << ID << "..." << std::endl;
   start();
}

ServiceThread::~ServiceThread()
{
   std::cout << "Stopping thread " << ID << "..." << std::endl;
   if(SocketDesc >= 0) {
      nsa_close(SocketDesc);
   }
   waitForFinish();
   std::cout << "Thread " << ID << " has been stopped." << std::endl;
}

void ServiceThread::run()
{
   // ====== Get command ====================================================
   char   command[8192];
   size_t cmdpos   = 0;
   bool   finished = false;
   while( (cmdpos < sizeof(command) - 1) && (!finished) ) {
      const ssize_t r = nsa_read(SocketDesc, &command[cmdpos], sizeof(command) - cmdpos);
      if(r <= 0) {
         if(r < 0) {
            std::cout << "Thread " << ID << ": Connection aborted - " << strerror(errno) << std::endl;
         }
         nsa_close(SocketDesc);
         SocketDesc = -1;
         return;
      }
      for(size_t i = 0; i < (size_t)r; i++) {
         if(command[cmdpos] == '\r') {
            command[cmdpos] = 0x00;
            finished = true;
            break;
         }
         cmdpos++;
      }
   }

   std::cout << "Command: ";
   safePrint(std::cout, command, cmdpos);
   std::cout << std::endl;

   // ====== Execute HTTP GET command =======================================
   ssize_t result = 0;
   if(strncasecmp(command, "GET ", 4) == 0) {
      std::string fileName = std::string((const char*)&command[4]);
      fileName = fileName.substr(0, fileName.find(' '));   // Remove <space>HTTP/1.x
      while(fileName[0] == '/') {                          // No absolute paths!
         fileName.erase(0, 1);
      }
      if(fileName == "") {   // No file name -> index.html
         fileName = "index.html";
      }

      if(fileName[0] != '.') {   // No access to top-level directories!
         std::cout << "Thread " << ID << ": Trying to upload file \""
                   << fileName << "\"..." << std::endl;
         const int fd = nsa_open(fileName.c_str(), 0, 0);
         if(fd >= 0) {
            const char* status = "HTTP/1.0 200 OK\r\n"
                                 "X-Frame-Options: SAMEORIGIN\r\n"
                                 "X-XSS-Protection: 1; mode=block\r\n"
                                 /* "X-Content-Type-Options: nosniff\r\n" */
                                 "Referrer-Policy: strict-origin\r\n"
                                 "Content-Security-Policy: default-src http:\r\n\r\n";
            result = nsa_write(SocketDesc, status, strlen(status));

            char str[8192];
            ssize_t s = nsa_read(fd, str, sizeof(str));
            while((s > 0) && (result > 0)) {
               result = nsa_write(SocketDesc, str, s);
               s = nsa_read(fd, str, sizeof(str));
            }
            nsa_close(fd);
         }
         else {
            std::cout << "Thread " << ID << ": File <" << fileName << "> not found!" << std::endl;
            const char* status = "HTTP/1.0 404 Not Found\r\n\r\n404 Not Found\r\n";
            result = nsa_write(SocketDesc, status, strlen(status));
         }
      }
      else {
         std::cout << "Thread " << ID << ": Request for . or .. not acceptable!" << std::endl;
         const char* status = "HTTP/1.0 406 Not Acceptable\r\n\r\n406 Not Acceptable\r\n";
         result = nsa_write(SocketDesc, status, strlen(status));
      }
   }
   else {
      std::cout << "Thread " << ID << ": Bad request!" << std::endl;
      const char* status = "HTTP/1.0 400 Bad Request\r\n\r\n400 Bad Request\r\n";
      result = nsa_write(SocketDesc, status, strlen(status));
   }

   if(result < 0) {
      std::cerr << "INFO: nsa_write() failed: " << strerror(errno) << std::endl;
   }

   // ====== Shutdown connection ============================================
   nsa_shutdown(SocketDesc, SHUT_RDWR);
   nsa_close(SocketDesc);
   SocketDesc = -1;
}




class ServiceThreadList
{
   public:
   ServiceThreadList();
   ~ServiceThreadList();
   void add(ServiceThread* thread);
   void remove(ServiceThread* thread);
   void removeFinished();
   void removeAll();

   private:
   struct ThreadListEntry {
      ThreadListEntry* Next;
      ServiceThread*   Object;
   };
   ThreadListEntry* ThreadList;
};

ServiceThreadList::ServiceThreadList()
{
   ThreadList = NULL;
}

ServiceThreadList::~ServiceThreadList()
{
   removeAll();
}

void ServiceThreadList::removeFinished()
{
   ThreadListEntry* entry = ThreadList;
   while(entry != NULL) {
      ThreadListEntry* next = entry->Next;
      if(entry->Object->hasFinished()) {
         remove(entry->Object);
      }
      entry = next;
   }
}

void ServiceThreadList::removeAll()
{
   ThreadListEntry* entry = ThreadList;
   while(entry != NULL) {
      remove(entry->Object);
      entry = ThreadList;
   }
}

void ServiceThreadList::add(ServiceThread* thread)
{
   ThreadListEntry* entry = new ThreadListEntry;
   entry->Next   = ThreadList;
   entry->Object = thread;
   ThreadList    = entry;
}

void ServiceThreadList::remove(ServiceThread* thread)
{
   ThreadListEntry* entry = ThreadList;
   ThreadListEntry* prev  = NULL;
   while(entry != NULL) {
      if(entry->Object == thread) {
         if(prev == NULL) {
            ThreadList = entry->Next;
         }
         else {
            prev->Next = entry->Next;
         }
         delete entry->Object;
         entry->Object = NULL;
         delete entry;
         return;
      }
      prev  = entry;
      entry = entry->Next;
   }
}




int ServerSocket = -1;

void intHandler(int signum)
{
   if(ServerSocket >= 0) {
      fputs("*** Ctrl-C ***\n", stderr);
      nsa_close(ServerSocket);
      ServerSocket = -1;
   }
}


int main(int argc, char** argv)
{
   // ====== Handle command-line arguments ==================================
   if(argc < 2) {
      std::cerr << "Usage: " << argv[0] << " [Port]" << std::endl;
      exit(1);
   }
   uint16_t port = atoi(argv[1]);


   // ====== Create and bind socket =========================================
   ServerSocket = nsa_socket(0, 0, 0, properties);
   if(ServerSocket <= 0) {
      perror("nsa_socket() call failed");
      exit(1);
   }
   if(nsa_bindn(ServerSocket, port, 0, NULL, 0) < 0) {
      perror("nsa_bindn() call failed");
      exit(1);
   }

   // ====== Turn socket into "listen" mode =================================
   if(nsa_listen(ServerSocket, 10) < 0) {
      perror("nsa_listen() call failed");
   }
   std::cout << "Waiting for requests on port " << port << " ..." << std::endl;

   // ====== Install SIGINT handler =========================================
   signal(SIGINT, &intHandler);


   // ====== Handle requests ================================================
   ServiceThreadList stl;
   for(;;) {
      // ====== Accept connection ===========================================
      sockaddr_storage remoteAddress;
      socklen_t        remoteAddressLength = sizeof(remoteAddress);
      const int        newSD = nsa_accept(ServerSocket, (sockaddr*)&remoteAddress, &remoteAddressLength);
      if(newSD < 0) {
         break;
      }

      // ====== Delete finished threads =====================================
      stl.removeFinished();

      // ====== Print information ===========================================
      char remoteHost[512];
      char remoteService[128];
      int error = getnameinfo((sockaddr*)&remoteAddress, remoteAddressLength,
                              (char*)&remoteHost, sizeof(remoteHost),
                              (char*)&remoteService, sizeof(remoteService),
                              NI_NUMERICHOST);
      if(error != 0) {
         std::cerr << "ERROR: getnameinfo() failed: " << gai_strerror(error) << std::endl;
      }
      else {
         std::cout << "Got connection from "
                   << remoteHost << ", service " << remoteService << ":" << std::endl;
      }

      // ====== Start new service thread ====================================
      stl.add(new ServiceThread(newSD));
   }


   // ====== Clean up =======================================================
   stl.removeAll();
   if(ServerSocket >= 0) {
      nsa_close(ServerSocket);
   }
   nsa_cleanup();

   std::cout << std::endl << "Terminated!" << std::endl;
   return(0);
}
