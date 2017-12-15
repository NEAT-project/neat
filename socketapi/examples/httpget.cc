/*
 * httpget.cc: File download via HTTP GET request
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
#include <regex>
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
   if(argc < 2) {
      std::cerr << "Usage: " << argv[0] << " [URL] [Output File]" << std::endl;
      exit(1);
   }

#if 0
   // ====== Get remote address (resolve hostname and service if necessary) ==
   struct addrinfo* ainfo = NULL;
   struct addrinfo  ainfohint;
   memset((char*)&ainfohint, 0, sizeof(ainfohint));
   ainfohint.ai_flags    = 0;
   ainfohint.ai_family   = AF_UNSPEC;
   ainfohint.ai_socktype = SOCK_STREAM;
   ainfohint.ai_protocol = IPPROTO_TCP;
   int error = getaddrinfo(argv[1], argv[2], &ainfohint, &ainfo);
   if(error != 0) {
      std::cerr << "ERROR: getaddrinfo() failed: " << gai_strerror(error) << std::endl;
      exit(1);
   }


   // ====== Create socket of appropriate type ===============================
   // int sd = nsa_socket(ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol, NULL);
   int sd = nsa_socket(0, 0, 0, properties);
   if(sd <= 0) {
      perror("nsa_socket() call failed");
      exit(1);
   }


   // ====== Convert remote address to human-readable format =================
   char remoteHost[512];
   char remoteService[128];
   error = getnameinfo(ainfo->ai_addr, ainfo->ai_addrlen,
                       (char*)&remoteHost, sizeof(remoteHost),
                       (char*)&remoteService, sizeof(remoteService),
                       NI_NUMERICHOST);
   if(error != 0) {
      std::cerr << "ERROR: getnameinfo() failed: " << gai_strerror(error) << std::endl;
      exit(1);
   }
   std::cout << "Connecting to remote address "
             << remoteHost << ", service " << remoteService << "..." << std::endl;


   // ====== Connect to remote node ==========================================
   if(nsa_connect(sd, ainfo->ai_addr, ainfo->ai_addrlen, NULL, 0) < 0) {
      perror("nsa_connect() call failed");
      exit(1);
   }
   freeaddrinfo(ainfo);
#endif

   // ====== Dissect URL =====================================================
   std::string url = std::string(argv[1]);
   std::regex  ex("(http|https)://([^/ :]+):?([^/ ]*)(.*)");
   std::cmatch what;
   if(!regex_match(url.c_str(), what, ex)) {
      std::cerr << "ERROR: Invalid URL " << argv[1] << "!" << std::endl;
      exit(1);
   }
   const std::string protocol = std::string(what[1].first, what[1].second);
   const std::string server   = std::string(what[2].first, what[2].second);
   const std::string port     = std::string(what[3].first, what[3].second);
   const std::string path     = std::string(what[4].first, what[4].second);
   uint16_t portNumber   = atoi(port.c_str());
   if(portNumber == 0) {
      portNumber = 80;
   }

   // ====== Connect to remote node ==========================================
   int sd = nsa_socket(0, 0, 0, properties);
   if(sd <= 0) {
      perror("nsa_socket() call failed");
      exit(1);
   }
   if(nsa_connectn(sd, server.c_str(), portNumber, NULL, NULL, 0) < 0) {
      perror("nsa_connect() call failed");
      exit(1);
   }

   // ====== Request webpage =================================================
   std::cout << "Connected! Sending HTTP GET..." << std::endl;
   char httpGet[1024];
   snprintf((char*)&httpGet, sizeof(httpGet),
            "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
            path.c_str(), server.c_str());

   ansiStyle(std::cout, COLOR_CYAN, COLOR_DEFAULT, ATTR_INTENSIVE);
   std::cout << httpGet;
   ansiReset(std::cout);
   std::cout.flush();
   if(nsa_write(sd, httpGet, strlen(httpGet)) < 0) {
      perror("nsa_write() call failed");
      exit(1);
   }

   // ====== Output file =====================================================
   int fd = -1;
   if(argc >= 3) {
      fd = nsa_open(argv[2], O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR);
      if(fd < 0) {
         perror("Unable to create output file");
         exit(1);
      }
   }

   // ====== Receive reply ===================================================
   std::cout << "Request sent. Waiting for answer..." << std::endl;
   bool success = false;
   for(;;) {
      char str[65536];

      ssize_t received = nsa_read(sd, (char*)&str, sizeof(str));
      if(received < 0) {
         perror("nsa_read() call failed");
         break;
      }
      else if(received == 0) {
         // Connection closed without error.
         success = true;
         break;
      }
      else {
         if(fd >= 0) {
            const ssize_t written = nsa_write(fd, str, received);
            if(written != received) {
               perror("Failed to write output");
               break;
            }
         }
         else {
            ansiStyle(std::cout, COLOR_BLUE, COLOR_DEFAULT, ATTR_INTENSIVE);
            safePrint(std::cout, str, received);
            ansiReset(std::cout);
         }
      }
   }


   // ====== Clean up ========================================================
   if(fd >= 0) {
      nsa_close(fd);
      if(!success) {
         if(unlink(argv[2]) == 0) {
            std::cerr << "Removed incomplete output file." << std::endl;
         }
      }
   }
   nsa_close(sd);
   nsa_cleanup();

   std::cout << std::endl << "Terminated!" << std::endl;
   return(0);
}
