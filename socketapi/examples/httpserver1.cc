/*
 * httpserver1.cc: HTTP server example
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


int main(int argc, char** argv)
{
   if(argc < 2) {
      cerr << "Usage: " << argv[0] << " [Port]" << endl;
      exit(1);
   }


   // ====== Get remote address (resolve hostname and service if necessary) =
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


   // ====== Create socket of appropriate type ==============================
   int sd = nsa_socket(ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol, properties);
   if(sd <= 0) {
      perror("nsa_socket() call failed");
      exit(1);
   }


   // ====== Bind to local port =============================================
   if(nsa_bind(sd, ainfo->ai_addr, ainfo->ai_addrlen) < 0) {
      perror("nsa_bind() call failed");
      exit(1);
   }


   // ====== Turn socket into "listen" mode =================================
   if(nsa_listen(sd, 10, NULL, 0) < 0) {
      perror("nsa_listen() call failed");
   }


   // ====== Print information ==============================================
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


   // ====== Handle requests ================================================
   for(;;) {
      // ====== Accept connection ===========================================
      sockaddr_storage remoteAddress;
      socklen_t        remoteAddressLength = sizeof(remoteAddress);
      int newSD = nsa_accept(sd, (sockaddr*)&remoteAddress, &remoteAddressLength);
      if(newSD < 0) {
         perror("nsa_accept() call failed");
         break;
      }


      // ====== Print information ===========================================
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


      // ====== Get command =================================================
      char   command[8192];
      size_t cmdpos   = 0;
      bool   finished = false;
      while( (cmdpos < sizeof(command) - 1) && (!finished) ) {
         const ssize_t r = nsa_read(newSD, &command[cmdpos], sizeof(command) - cmdpos);
         if(r <= 0) {
            if(r < 0) {
               perror("nsa_read() call failed");
               exit(1);
            }
            exit(1);
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

      cout << "Command: ";
      safePrint(cout, command, cmdpos);
      cout << endl;


      // ====== Execute HTTP GET command ====================================
      ssize_t result = -1;
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
            cout << "Trying to upload file \"" << fileName << "\"..." << endl;
            ifstream is(fileName.c_str(), ios::binary);
            if(is.good()) {
               const char* status = "HTTP/1.0 200 OK\r\n"
                                    "X-Frame-Options: SAMEORIGIN\r\n"
                                    "X-XSS-Protection: 1; mode=block\r\n"
                                    "X-Content-Type-Options: nosniff\r\n"
                                    "Referrer-Policy: strict-origin\r\n"
                                    "Content-Security-Policy: default-src http:\r\n\r\n";
               result = nsa_write(newSD, status, strlen(status));

               char str[256];
               streamsize s = is.rdbuf()->sgetn(str, sizeof(str));
               while((s > 0) && (result > 0)) {
                  result = nsa_write(newSD, str, s);
                  s = is.rdbuf()->sgetn(str, sizeof(str));
               }
            }
            else {
               cout << "File not found!" << endl;
               const char* status = "HTTP/1.0 404 Not Found\r\n\r\n404 Not Found\r\n";
               result = nsa_write(newSD, status, strlen(status));
            }
         }
         else {
            cout << "Request for . or .. not acceptable!" << endl;
            const char* status = "HTTP/1.0 406 Not Acceptable\r\n\r\n406 Not Acceptable\r\n";
            result = nsa_write(newSD, status, strlen(status));
         }
      }
      else {
         cout << "Bad request!" << endl;
         const char* status = "HTTP/1.0 400 Bad Request\r\n\r\n400 Bad Request\r\n";
         result = nsa_write(newSD, status, strlen(status));
      }
      cout << "Command completed." << endl;


      // ====== Shutdown connection =========================================
      nsa_shutdown(newSD, SHUT_RDWR);
      nsa_close(newSD);
   }


   // ====== Clean up =======================================================
   freeaddrinfo(ainfo);
   nsa_close(sd);
   nsa_cleanup();

   cout << endl << "Terminated!" << endl;
   return(0);
}
