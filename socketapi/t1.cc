#include <neat-socketapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int main(int argc, char** argv)
{
   int sd = ext_socket(AF_INET6, SOCK_SEQPACKET, IPPROTO_SCTP);
   if(sd > 0) {
      printf("sd=%d\n", sd);
      ext_close(sd);
   }
   else {
      printf("ext_socket() failed!\n");
   }
   return 0;
}
