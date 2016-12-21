/*
 * httpserver2-select.cc: select()-based HTTP server example
 *
 * Copyright (C) 2003-2017 by Thomas Dreibholz
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

#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <neat-socketapi.h>


#include "ansistyle.h"
#include "safeprint.h"


using namespace std;


static const char* properties = "{\
    \"transport\": [\
        {\
            \"value\": \"SCTP\",\
            \"precedence\": 1\
        },\
        {\
            \"value\": \"TCP\",\
            \"precedence\": 1\
        }\
    ]\
}";\


void handleHTTPCommand(int sd, const unsigned int id, char* command)
{
   ssize_t result = -1;

   // ====== Execute HTTP GET command =====================================
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
         cout << "Client " << id << ": Trying to upload file \""
              << fileName << "\"..." << endl;
         ifstream is(fileName.c_str(), ios::binary);
         if(is.good()) {
            const char* status = "HTTP/1.0 200 OK\r\n\r\n";
            result = nsa_write(sd, status, strlen(status));

            char str[8192];
            streamsize s = is.rdbuf()->sgetn(str, sizeof(str));
            while((s > 0) && (result > 0)) {
               result = nsa_write(sd, str, s);
               s = is.rdbuf()->sgetn(str, sizeof(str));
            }
         }
         else {
            cout << "Client " << id << ": File <" << fileName << "> not found!" << endl;
            const char* status = "HTTP/1.0 404 Not Found\r\n\r\n404 Not Found\r\n";
            result = nsa_write(sd, status, strlen(status));
         }
      }
      else {
         cout << "Client " << id << ": Request for . or .. not acceptable!" << endl;
         const char* status = "HTTP/1.0 406 Not Acceptable\r\n\r\n406 Not Acceptable\r\n";
         result = nsa_write(sd, status, strlen(status));
      }
   }
   else {
      cout << "Client " << id << ": Bad request!" << endl;
      const char* status = "HTTP/1.0 400 Bad Request\r\n\r\n400 Bad Request\r\n";
      result = nsa_write(sd, status, strlen(status));
   }
}




class ClientList
{
   public:
   ClientList();
   ~ClientList();
   void add(const int socketDescriptor);
   void remove(const int socketDescriptor);
   void removeAll();
   int  getEvents(fd_set* readSet);
   void handleEvents(fd_set* readSet);

   private:
   struct ClientListEntry {
      ClientListEntry* Next;
      int              SocketDescriptor;
      unsigned int     ID;
      char             Command[1024];
      unsigned int     CommandPos;
   };
   ClientListEntry* FirstClient;

   void handleEvent(ClientListEntry* entry);
};


ClientList::ClientList()
{
   FirstClient = NULL;
}

ClientList::~ClientList()
{
   removeAll();
}

void ClientList::removeAll()
{
   ClientListEntry* entry = FirstClient;
   while(entry != NULL) {
      remove(entry->SocketDescriptor);
      entry = FirstClient;
   }
}

void ClientList::add(const int socketDescriptor)
{
   static unsigned int IDCounter = 0;

   ClientListEntry* entry = new ClientListEntry;
   entry->Next             = FirstClient;
   entry->SocketDescriptor = socketDescriptor;
   entry->CommandPos       = 0;
   entry->ID               = ++IDCounter;
   FirstClient              = entry;

   cout << "New client " << entry->ID << endl;
}

void ClientList::remove(const int socketDescriptor)
{
   ClientListEntry* entry = FirstClient;
   ClientListEntry* prev  = NULL;
   while(entry != NULL) {
      if(entry->SocketDescriptor == socketDescriptor) {
         if(prev == NULL) {
            FirstClient = entry->Next;
         }
         else {
            prev->Next = entry->Next;
         }
         entry->SocketDescriptor = -1;
         cout << "Removing client " << entry->ID << endl;
         delete entry;
         return;
      }
      prev  = entry;
      entry = entry->Next;
   }
}

int ClientList::getEvents(fd_set* readSet)
{
   ClientListEntry* entry = FirstClient;
   int n = 0;
   while(entry != NULL) {
      FD_SET(entry->SocketDescriptor, readSet);
      n = max(n, entry->SocketDescriptor);
      entry = entry->Next;
   }
   return(n);
}

void ClientList::handleEvents(fd_set* readSet)
{
   for(size_t i = 0;i < FD_SETSIZE;i++) {
      if(FD_ISSET(i, readSet)) {
         ClientListEntry* entry = FirstClient;
         while(entry != NULL) {
            if(FD_ISSET(entry->SocketDescriptor, readSet)) {
               handleEvent(entry);
               break;
            }
            entry = entry->Next;
         }
      }
   }
}

void ClientList::handleEvent(ClientList::ClientListEntry* entry)
{
   if(entry->CommandPos < sizeof(entry->Command)) {
      ssize_t received = nsa_read(entry->SocketDescriptor,
                                  (char*)&entry->Command[entry->CommandPos],
                                  sizeof(entry->Command) - entry->CommandPos);
      if(received > 0) {
         entry->CommandPos += received;
         for(size_t i = 0;i < entry->CommandPos;i++) {
            if(entry->Command[i] == '\r') {
               entry->Command[i] = 0x00;

               cout << "Command: ";
               safePrint(cout, entry->Command, i);
               cout << endl;

               handleHTTPCommand(entry->SocketDescriptor, entry->ID,
                                 entry->Command);

               nsa_shutdown(entry->SocketDescriptor, SHUT_RDWR);
               nsa_close(entry->SocketDescriptor);
               remove(entry->SocketDescriptor);
               break;
            }
         }
      }
      else {
         remove(entry->SocketDescriptor);
      }
   }
}




bool breakDetected = false;

void intHandler(int signum)
{
   if(!breakDetected) {
      fputs("*** Ctrl-C ***\n", stderr);
      breakDetected = true;
   }
}


int main(int argc, char** argv)
{
   if(argc < 2) {
      cerr << "Usage: " << argv[0] << " [Port]" << endl;
      exit(1);
   }


   // ====== Get remote address (resolve hostname and service if necessary) ==
   struct addrinfo* ainfo = NULL;
   struct addrinfo  ainfohint;
   memset((char*)&ainfohint, 0, sizeof(ainfohint));
   // AI_PASSIVE will set address to the ANY address.
   ainfohint.ai_flags    = AI_PASSIVE;
   ainfohint.ai_family   = AF_UNSPEC;
   ainfohint.ai_socktype = SOCK_STREAM;
   ainfohint.ai_protocol = IPPROTO_TCP;
   int error = getaddrinfo(NULL, argv[1], &ainfohint, &ainfo);
   if(error != 0) {
      cerr << "ERROR: getaddrinfo() failed: " << gai_strerror(error) << endl;
      exit(1);
   }


   // ====== Create socket of appropriate type ===============================
   int sd = nsa_socket(ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol, properties);
   if(sd <= 0) {
      perror("nsa_socket() call failed");
      exit(1);
   }


   // ====== Bind to local port ==============================================
   if(nsa_bind(sd, ainfo->ai_addr, ainfo->ai_addrlen) < 0) {
      perror("nsa_bind() call failed");
      exit(1);
   }

#if 0
   if(nsa_fcntl(sd, F_SETFL, O_NONBLOCK) != 0) {
      perror("nsa_fcntl() call failed");
      exit(1);
   }
#endif


   // ====== Turn socket into "listen" mode ==================================
   if(nsa_listen(sd, 10) < 0) {
      perror("listen() call failed");
   }


   // ====== Install SIGINT handler ==========================================
   signal(SIGINT, &intHandler);


   // ====== Print information ===============================================
   char localHost[512];
   char localService[128];
   error = getnameinfo(ainfo->ai_addr, ainfo->ai_addrlen,
                       (char*)&localHost, sizeof(localHost),
                       (char*)&localService, sizeof(localService),
                       NI_NUMERICHOST);
   if(error != 0) {
      cerr << "ERROR: getnameinfo() failed: " << gai_strerror(error) << endl;
      exit(1);
   }
   cout << "Waiting for requests at address "
        << localHost << ", service " << localService << "..." << endl;


   // ====== Handle requests =================================================
   ClientList clientList;
   while(!breakDetected) {
      fd_set readSet;
      FD_ZERO(&readSet);

      int n = clientList.getEvents(&readSet);
      FD_SET(sd, &readSet);
      n = max(n, sd);

      timeval timeout;
      timeout.tv_sec  = 1;
      timeout.tv_usec = 0;

      int result = nsa_select(n + 1, &readSet, NULL, NULL, &timeout);
      if(result > 0) {
         clientList.handleEvents(&readSet);
         if(FD_ISSET(sd, &readSet)) {
            // ====== Accept connection ============================================
            sockaddr_storage remoteAddress;
            socklen_t        remoteAddressLength = sizeof(remoteAddress);
            int newSD = nsa_accept(sd, (sockaddr*)&remoteAddress, &remoteAddressLength);
            if(newSD < 0) {
               break;
            }

            // ====== Print information ============================================
            char remoteHost[512];
            char remoteService[128];
            error = getnameinfo((sockaddr*)&remoteAddress, remoteAddressLength,
                                (char*)&remoteHost, sizeof(remoteHost),
                                (char*)&remoteService, sizeof(remoteService),
                                NI_NUMERICHOST);
            if(error != 0) {
               cerr << "ERROR: getnameinfo() failed: " << gai_strerror(error) << endl;
               exit(1);
            }
            cout << "Got connection from "
                 << remoteHost << ", service " << remoteService << ":" << endl;


            // ====== Start new service thread =====================================
            clientList.add(newSD);
         }
      }
   }


   // ====== Clean up ========================================================
   clientList.removeAll();
   freeaddrinfo(ainfo);
   if(sd >= 0) {
      nsa_close(sd);
   }
   nsa_cleanup();

   cout << endl << "Terminated!" << endl;
   return 0;
}
