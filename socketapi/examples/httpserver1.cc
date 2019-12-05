/*
 * httpserver1.cc: HTTP server example
 *
 * Copyright (C) 2003-2020 by Thomas Dreibholz
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


static const char* properties = "{\
   \"transport\": {\
      \"value\": [ \"MPTCP\", \"SCTP\", \"SCTP/UDP\", \"TCP\" ],\
      \"precedence\": 1\
   }\
}";


int main(int argc, char** argv)
{
   // ====== Handle command-line arguments ==================================
   if(argc < 2) {
      std::cerr << "Usage: " << argv[0] << " [Port]" << std::endl;
      exit(1);
   }
   uint16_t port = atoi(argv[1]);


   // ====== Create and bind socket =========================================
   int sd = nsa_socket(0, 0, 0, properties);
   if(sd <= 0) {
      perror("nsa_socket() call failed");
      exit(1);
   }
   if(nsa_bindn(sd, port, 0, NULL, 0) < 0) {
      perror("nsa_bindn() call failed");
      exit(1);
   }

   // ====== Turn socket into "listen" mode =================================
   if(nsa_listen(sd, 10) < 0) {
      perror("nsa_listen() call failed");
   }
   std::cout << "Waiting for requests on port " << port << " ..." << std::endl;


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

      // ====== Get command =================================================
      char   command[8192];
      size_t cmdpos   = 0;
      bool   finished = false;
      while( (cmdpos < sizeof(command) - 1) && (!finished) ) {
         const ssize_t r = nsa_read(newSD, &command[cmdpos], sizeof(command) - cmdpos);
         if(r <= 0) {
            if(r < 0) {
               perror("nsa_read() call failed");
            }
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
            std::cout << "Trying to upload file \"" << fileName << "\"..." << std::endl;
            int fd = nsa_open(fileName.c_str(), 0, 0);
            if(fd >= 0) {
               const char* status = "HTTP/1.0 200 OK\r\n"
                                    "X-Frame-Options: SAMEORIGIN\r\n"
                                    "X-XSS-Protection: 1; mode=block\r\n"
                                    /* "X-Content-Type-Options: nosniff\r\n" */
                                    "Referrer-Policy: strict-origin\r\n"
                                    "Content-Security-Policy: default-src http:\r\n\r\n";
               result = nsa_write(newSD, status, strlen(status));

               char str[256];
               ssize_t s = nsa_read(fd, str, sizeof(str));
               while((s > 0) && (result > 0)) {
                  result = nsa_write(newSD, str, s);
                  s = nsa_read(fd, str, sizeof(str));
               }
            }
            else {
               std::cout << "File not found!" << std::endl;
               const char* status = "HTTP/1.0 404 Not Found\r\n\r\n404 Not Found\r\n";
               result = nsa_write(newSD, status, strlen(status));
            }
         }
         else {
            std::cout << "Request for . or .. not acceptable!" << std::endl;
            const char* status = "HTTP/1.0 406 Not Acceptable\r\n\r\n406 Not Acceptable\r\n";
            result = nsa_write(newSD, status, strlen(status));
         }
      }
      else {
         std::cout << "Bad request!" << std::endl;
         const char* status = "HTTP/1.0 400 Bad Request\r\n\r\n400 Bad Request\r\n";
         result = nsa_write(newSD, status, strlen(status));
      }
      if(result < 0) {
         std::cerr << "INFO: nsa_write() failed: " << strerror(errno) << std::endl;
      }
      std::cout << "Command completed." << std::endl;


      // ====== Shutdown connection =========================================
      nsa_shutdown(newSD, SHUT_RDWR);
      nsa_close(newSD);
   }

   // ====== Clean up =======================================================
   nsa_close(sd);
   nsa_cleanup();

   std::cout << std::endl << "Terminated!" << std::endl;
   return(0);
}
