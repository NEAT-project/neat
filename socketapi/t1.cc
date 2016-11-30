#include <neat-socketapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


static char* properties = "{\
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
   int sd = nsa_socket(AF_INET6, SOCK_SEQPACKET, IPPROTO_SCTP, properties);
   if(sd >= 0) {
      printf("sd=%d\n", sd);
      nsa_close(sd);
   }
   else {
      printf("nsa_socket() failed!\n");
   }

   nsa_cleanup();
   return 0;
}
