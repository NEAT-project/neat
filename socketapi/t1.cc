#include <neat-socketapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>


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

      struct sockaddr* addrs = NULL;
      const int n = nsa_getpaddrs(newSD, 0, &addrs);
      if(n > 0) {
         struct sockaddr* a = addrs;
         for(int i = 0; i < n; i++) {
            switch(a->sa_family) {
               case AF_INET:
                  printf("Address %d/%d: IPv4\n", i, n);
                  a = (struct sockaddr*)((long)a + (long)sizeof(sockaddr_in));
                break;
               case AF_INET6:
                  printf("Address %d/%d: IPv6\n", i, n);
                  a = (struct sockaddr*)((long)a + (long)sizeof(sockaddr_in6));
               default:
                  assert(false);
                break;
            }
         }
         free(addrs);
      }

      char buffer[1024];
      ssize_t r = nsa_read(newSD, (char*)&buffer, sizeof(buffer));
      if(r > 0) {
         printf("r=%d\n", (int)r);
         if(nsa_write(newSD, buffer, r) < 0) {
            perror("nsa_write() failed");
         }
      }

      nsa_close(newSD);
   }
   else {
      perror("nsa_accept() failed");
   }

   nsa_close(sd);

   nsa_cleanup();
   return 0;
}
