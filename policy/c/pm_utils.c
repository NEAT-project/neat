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

/* translate no more than N characters into upper case */
char *
strnupr(char *dest, const char *src, size_t n) {
    if(strlen(src) > n) {
        return NULL;
    }
    strcpy(dest, src);

    int i;
    for(i = 0; i < strlen(dest) && i < n; i++) {
        dest[i] = toupper(dest[i]);
    }

    return dest;
}

int isnumeric(char *str) {
    char *c;

    for (c = str; *c; c++) {
        if(!isdigit(*c)) {
            return 0;
        }
    }

    return 1;
}