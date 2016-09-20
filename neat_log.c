#include <stdint.h>

#include "neat_core.h"

#ifdef NEAT_LOG
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "neat_log.h"

uint8_t neat_log_level = NEAT_LOG_DEBUG;
struct timeval tv_init;
FILE *neat_log_fd = NULL;

/*
 * Initiate log system
 *  - currently supports stderr and file
 */
uint8_t neat_log_init() {
    const char* env_log_level;
    const char* env_log_file;

    env_log_level = getenv("NEAT_LOG_LEVEL");
    env_log_file = getenv("NEAT_LOG_FILE");
    gettimeofday(&tv_init, NULL);


    // use stderr as default output until init finished...
    neat_log_fd = stderr;

    // determine log level
    if (env_log_level == NULL) {
        neat_log(NEAT_LOG_INFO, "%s - NEAT_LOG_LEVEL : default", __func__);
    } else if (strcmp(env_log_level,"NEAT_LOG_DEBUG") == 0) {
        neat_log(NEAT_LOG_INFO, "%s - NEAT_LOG_LEVEL : NEAT_LOG_DEBUG", __func__);
        neat_log_level = NEAT_LOG_DEBUG;
    } else if (strcmp(env_log_level,"NEAT_LOG_INFO") == 0) {
        neat_log(NEAT_LOG_INFO, "%s - NEAT_LOG_LEVEL : NEAT_LOG_INFO", __func__);
        neat_log_level = NEAT_LOG_INFO;
    } else if (strcmp(env_log_level,"NEAT_LOG_WARNING") == 0) {
        neat_log(NEAT_LOG_INFO, "%s - NEAT_LOG_LEVEL : NEAT_LOG_WARNING", __func__);
        neat_log_level = NEAT_LOG_WARNING;
    } else if (strcmp(env_log_level,"NEAT_LOG_ERROR") == 0) {
        neat_log(NEAT_LOG_INFO, "%s - NEAT_LOG_LEVEL : NEAT_LOG_ERROR", __func__);
        neat_log_level = NEAT_LOG_ERROR;
    } else if (strcmp(env_log_level,"NEAT_LOG_OFF") == 0) {
        neat_log(NEAT_LOG_INFO, "%s - NEAT_LOG_LEVEL : NEAT_LOG_OFF", __func__);
        neat_log_level = NEAT_LOG_OFF;
    }

    // determine output fd
    if (env_log_file != NULL) {
        neat_log(NEAT_LOG_INFO, "%s - using logfile: %s", __func__, env_log_file);
        neat_log_fd = fopen (env_log_file, "w");

        if (neat_log_fd == NULL) {
            neat_log_fd = stderr;
            neat_log(NEAT_LOG_ERROR, "%s - could not open logfile, using stderr", __func__);
            return RETVAL_FAILURE;
        }
    }
    neat_log(NEAT_LOG_INFO, "%s - opening logfile ...", __func__);

    return RETVAL_SUCCESS;
}

/*
 * Write log entry
 */
void neat_log(uint8_t level, const char* format, ...) {

    struct timeval tv_now, tv_diff;
    // skip unwanted loglevels
    if (neat_log_level < level) {
        return;
    }

    if (neat_log_fd == NULL) {
        fprintf(stderr, "neat_log_fd is NULL - neat_log_init() required!\n");
        return;
    }

    gettimeofday(&tv_now, NULL);

    tv_diff.tv_sec = tv_now.tv_sec - tv_init.tv_sec;

    if (tv_init.tv_usec <= tv_now.tv_usec) {
        tv_diff.tv_usec = tv_now.tv_usec - tv_init.tv_usec;
    } else {
        tv_diff.tv_sec -= 1;
        tv_diff.tv_usec = 1000000 + tv_now.tv_usec - tv_init.tv_usec;
    }

    fprintf(neat_log_fd, "[%4ld.%06ld]", (long)tv_diff.tv_sec, (long)tv_diff.tv_usec);

    switch (level) {
        case NEAT_LOG_ERROR:
            fprintf(neat_log_fd, "[ERR] ");
            break;
        case NEAT_LOG_WARNING:
            fprintf(neat_log_fd, "[WRN] ");
            break;
        case NEAT_LOG_INFO:
            fprintf(neat_log_fd, "[INF] ");
            break;
        case NEAT_LOG_DEBUG:
            fprintf(neat_log_fd, "[DBG] ");
            break;
    }

    va_list argptr;
    va_start(argptr, format);
    vfprintf(neat_log_fd, format, argptr);
    va_end(argptr);

    fprintf(neat_log_fd, "\n"); // xxx:ugly solution...
}

/*
 * Write log entry for usrsctp
 */

void neat_log_usrsctp(const char* format, ...) {

    if (neat_log_fd == NULL) {
        fprintf(stderr, "neat_log_fd is NULL - neat_log_init() required!\n");
        return;
    }

    fprintf(neat_log_fd, "[DBG] ");

    va_list argptr;
    va_start(argptr, format);
    vfprintf(neat_log_fd, format, argptr);
    va_end(argptr);
}

/*
 * Close logfile
 */
uint8_t neat_log_close() {
    neat_log(NEAT_LOG_INFO, "%s - closing logfile ...", __func__);
    if (neat_log_fd != stderr) {
        if (fclose(neat_log_fd) == 0) {
            return RETVAL_SUCCESS;
        } else {
            return RETVAL_FAILURE;
        }
    }

    return RETVAL_SUCCESS;
}

#else // NEAT_LOG
    uint8_t neat_log_init() {
        return RETVAL_SUCCESS;
    }

    void neat_log(uint8_t level, const char* format, ...) {
        return;
    }

    void neat_log_usrsctp(const char* format, ...) {
        return;
    }

    uint8_t neat_log_close() {
        return RETVAL_SUCCESS;
    }


#endif
