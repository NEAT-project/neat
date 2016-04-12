#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "neat_log.h"
#include "neat_core.h"

uint8_t neat_log_level = NEAT_LOG_INFO;
FILE *neat_log_fd = NULL;

/*
 * initiate log system
 *  - currently supports stderr and file
 */
uint8_t neat_log_init() {
    const char* env_log_level = getenv("NEAT_LOG_LEVEL");
    const char* env_log_file = getenv("NEAT_LOG_FILE");

    neat_log_level = NEAT_LOG_DEBUG;
    neat_log_fd = stderr;

    // determine Loglevel
    if (env_log_level == NULL) {
        neat_log(NEAT_LOG_DEBUG, "%s - NEAT_LOG_LEVEL : default", __FUNCTION__);
    } else if (strcmp(env_log_level,"NEAT_LOG_DEBUG") == 0) {
        neat_log(NEAT_LOG_DEBUG, "%s - NEAT_LOG_LEVEL : NEAT_LOG_DEBUG", __FUNCTION__);
        neat_log_level = NEAT_LOG_DEBUG;
    } else if (strcmp(env_log_level,"NEAT_LOG_INFO") == 0) {
        neat_log(NEAT_LOG_DEBUG, "%s - NEAT_LOG_LEVEL : NEAT_LOG_INFO", __FUNCTION__);
        neat_log_level = NEAT_LOG_INFO;
    } else if (strcmp(env_log_level,"NEAT_LOG_WARNING") == 0) {
        neat_log(NEAT_LOG_DEBUG, "%s - NEAT_LOG_LEVEL : NEAT_LOG_WARNING", __FUNCTION__);
        neat_log_level = NEAT_LOG_WARNING;
    } else if (strcmp(env_log_level,"NEAT_LOG_ERROR") == 0) {
        neat_log(NEAT_LOG_DEBUG, "%s - NEAT_LOG_LEVEL : NEAT_LOG_ERROR", __FUNCTION__);
        neat_log_level = NEAT_LOG_ERROR;
    } else if (strcmp(env_log_level,"NEAT_LOG_OFF") == 0) {
        neat_log(NEAT_LOG_DEBUG, "%s - NEAT_LOG_LEVEL : NEAT_LOG_OFF", __FUNCTION__);
        neat_log_level = NEAT_LOG_OFF;
    }

    // determine output fd
    if (env_log_file != NULL) {
        neat_log(NEAT_LOG_DEBUG, "%s - using logfile: %s", __FUNCTION__, env_log_file);
        neat_log_fd = fopen (env_log_file, "w");

        if (neat_log_fd == NULL) {
            neat_log_fd = stderr;
            neat_log(NEAT_LOG_ERROR, "%s - could not open logfile, using stderr", __FUNCTION__);
            return RETVAL_FAILURE;
        }
    }

    return RETVAL_SUCCESS;
}

void neat_log(uint8_t level, const char* format, ...) {

    if (neat_log_level < level) {
        return;
    }

    if (neat_log_fd == NULL) {
        fprintf(stderr, "neat_log_fd is NULL\n");
        return;
    }

    va_list argptr;
    va_start(argptr, format);
    vfprintf(neat_log_fd, format, argptr);
    va_end(argptr);
    fprintf(neat_log_fd, "\n");
}

uint8_t neat_log_close() {
    if (neat_log_fd != stderr) {
        if (fclose(neat_log_fd) == 0) {
            return RETVAL_SUCCESS;
        } else {
            return RETVAL_FAILURE;
        }
    }

    return RETVAL_SUCCESS;

}
