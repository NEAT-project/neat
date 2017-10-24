#include <neat-socketapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>


int main(int argc, char** argv)
{
   int sd = nsa_open("/dev/random", O_RDONLY, 0);
   if(sd >= 0) {
      while(1) {
         char buffer[16];

         pollfd pfd;
         pfd.fd     = sd;
         pfd.events = POLLIN;

         int p = nsa_poll(&pfd, 1, 1000);
         if(p > 0) {
            ssize_t r = nsa_read(sd, (char*)&buffer, sizeof(buffer));
            if(r <= 0) {
               perror("nsa_read()");
               break;
            }
            printf("r=%d\n", (int)r);
         }
         else {
            printf("timeout\n");
         }
      }
   }

   nsa_close(sd);
   nsa_cleanup();
   return 0;
}
