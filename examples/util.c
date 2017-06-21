#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <sys/stat.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>

int
read_file(const char *filename, const char **bufptr)
{
    int rc = -1;
    struct stat stat_buffer;
    char *buffer = NULL;
    FILE *f = NULL;
    size_t file_size, offset = 0;

    if ((rc = stat(filename, &stat_buffer)) < 0) {
        fprintf(stderr, "%s - stat failed - {%s}\n", __func__, filename);
        goto error;
    }

    assert(stat_buffer.st_size >= 0);

    file_size = (size_t)stat_buffer.st_size;

    buffer = (char*)malloc(file_size + 1);
    if (!buffer) {
        rc = -ENOMEM;
        fprintf(stderr, "%s - malloc failed\n", __func__);
        goto error;
    }

    f = fopen(filename, "r");
    if (!f) {
        rc = -EIO;
        fprintf(stderr, "%s - fopen failed\n", __func__);
        goto error;
    }

    do {
        size_t bytes_read = fread(buffer + offset, 1, file_size - offset, f);
        if (bytes_read < file_size - offset && ferror(f)) {
            fprintf(stderr, "%s - fread failed\n", __func__);
            goto error;
        }
        offset += bytes_read;
    } while (offset < file_size);

    fclose(f);

    buffer[file_size] = 0;

    *bufptr = buffer;
    return file_size;
error:
    if (buffer)
        free(buffer);
    if (f)
        fclose(f);
    *bufptr = NULL;
    return rc;
}

/*
    print human readable file sizes - helper function
*/
char
*filesize_human(double bytes, char *buffer, size_t buffersize)
{
    uint8_t i = 0;
    const char* units[] = {"B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};

    while (bytes > 1000) {
        bytes /= 1000;
        i++;

        if (i > 8) {
            fprintf(stderr, "%s - YB should be enough - something went wrong\n", __func__);
            exit(EXIT_FAILURE);
        }
    }
    snprintf(buffer, buffersize, "%.*f %s", i, bytes, units[i]);
    return buffer;
}
