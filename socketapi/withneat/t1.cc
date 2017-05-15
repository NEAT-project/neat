#include <stdarg.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


void vtest1(const char* text, ...)
{
   printf("%s", text);

   va_list list;
   va_start(list, text);
   int n;
   while( (n = va_arg(list, int)) > 0 ) {
      printf("\t%d", n);
   }
   va_end(list);

   puts("");      
}

extern inline void vtest2(const char* text, ...)
{
//    va_list list;
//    va_list list2;
//    va_start(list, text);
//    va_copy(list, list2);
   vtest1(text, __builtin_va_arg_pack ());
//    va_end(list);   
}


int main(int argc, char** argv)
{
   puts("Hello World!");
   vtest1("Test", 1, 2, 3, 0);
   vtest2("Test", 5, 4, 3, 2, 1, 0);
   
   int fd = open("/tmp/x0.txt", O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
   printf("fd=%d\n", fd);   
   if(fd > 0) {
      ssize_t w = write(fd, "Test", 4);
      if(w < 0) { puts("Write Error!"); }
      close(fd);
   }
   else perror("open() failed");
}
