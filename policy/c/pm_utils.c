#include <ctype.h>
#include <string.h>

/* translate no more than N characters into lower case */
char *
strnlwr(char *dest, const char *src, size_t n) {
    if(strlen(src) > n) {
        return NULL;
    }
    strncpy(dest, src, n);

    int i;
    for(i = 0; i < strlen(dest) && i < n; i++) {
        dest[i] = tolower(dest[i]);
    }

    return dest;
}
