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

//         {\
//             \"value\": \"SCTP\",\
//             \"precedence\": 1\
//         },\

static const char* properties = "{\
    \"transport\": [\
        {\
            \"value\": \"TCP\",\
            \"precedence\": 1\
        }\
    ]\
}";\


int main(int argc, char** argv)
{
   if(argc < 4) {
      cerr << "Usage: " << argv[0] << " [Remote Host] [Remote Service] [File]" << endl;
      exit(1);
   }


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
      cerr << "ERROR: getaddrinfo() failed: " << gai_strerror(error) << endl;
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
      cerr << "ERROR: getnameinfo() failed: " << gai_strerror(error) << endl;
      exit(1);
   }
   cout << "Connecting to remote address "
        << remoteHost << ", service " << remoteService << "..." << endl;


   // ====== Connect to remote node ==========================================
   if(nsa_connect(sd, ainfo->ai_addr, ainfo->ai_addrlen) < 0) {
      perror("nsa_connect() call failed");
      exit(1);
   }
   freeaddrinfo(ainfo);


   // ====== Request webpage =================================================
   cout << "Connected! Sending HTTP GET..." << endl;
   char httpGet[1024];
   snprintf((char*)&httpGet, sizeof(httpGet),
            "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
            argv[3], argv[1]);

   ansiStyle(cout, COLOR_CYAN, COLOR_DEFAULT, ATTR_INTENSIVE);
   cout << httpGet;
   ansiReset(cout);
   cout.flush();
   if(nsa_write(sd, httpGet, strlen(httpGet)) < 0) {
      perror("nsa_write() call failed");
      exit(1);
   }


   // ====== Receive reply ===================================================
   cout << "Request sent. Waiting for answer..." << endl;
   for(;;) {
      char str[65536];

      ssize_t received = nsa_read(sd, (char*)&str, sizeof(str));
      if(received < 0) {
         perror("nsa_read() call failed");
         break;
      }
      else if(received == 0) {
         // Connection closed without error.
         break;
      }
      else {
         ansiStyle(cout, COLOR_BLUE, COLOR_DEFAULT, ATTR_INTENSIVE);
         safePrint(cout, str, received);
         ansiReset(cout);
      }
   }


   // ====== Clean up ========================================================
   nsa_close(sd);
   nsa_cleanup();

   cout << endl << "Terminated!" << endl;
   return(0);
}
