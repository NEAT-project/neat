#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>

void neat_log(uint8_t level, const char* format, ...) {
    va_list argptr;
    va_start(argptr, format);
    vfprintf(stderr, format, argptr);
    va_end(argptr);
    fprintf(stderr, "\n");
}
