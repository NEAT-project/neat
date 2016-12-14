#include <neat-socketapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


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
   int sd = nsa_socket(AF_INET6, SOCK_SEQPACKET, IPPROTO_SCTP, properties);
   if(sd < 0) {
      perror("nsa_socket() failed");
      exit(1);
   }
   printf("sd=%d\n", sd);


   sockaddr_in local;
   memset(&local, 0, sizeof(local));
   local.sin_family = AF_INET;
   local.sin_port   = htons(8888);
   if(nsa_bind(sd, (sockaddr*)&local, sizeof(local)) < 0) {
      perror("nsa_bind() failed");
      exit(1);
   }

   if(nsa_listen(sd, 10) < 0) {
      perror("nsa_listen() failed");
      exit(1);
   }

   puts("### LISTENING ... ###");

   int newSD = nsa_accept(sd, NULL, NULL);
   if(newSD >= 0) {
      puts("### ACCEPTED ###");

      if(nsa_write(newSD, "TEST\n", 5) < 0) {
         perror("nsa_write() failed");
      }

      nsa_close(newSD);
   }
   else {
      perror("nsa_accept() failed");
   }


   nsa_cleanup();
   return 0;
}
