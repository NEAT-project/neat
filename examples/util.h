#ifndef EXAMPLES_UTIL_INCLUDE_H
#define EXAMPLES_UTIL_INCLUDE_H
#include <stdlib.h>

int read_file(const char *filename, char **bufptr);
char *filesize_human(double bytes, char *buffer, size_t buffersize);

#endif /* ifndef EXAMPLES_UTIL_INCLUDE_H */
