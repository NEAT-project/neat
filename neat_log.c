#include <stdint.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_core.h"

#ifdef NEAT_LOG
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "neat_log.h"

#define KNRM  "\x1B[0m"
#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"

/*
 * Initiate log system
 *  - currently supports stderr and file
 */
uint8_t
neat_log_init(struct neat_ctx *ctx)
{
    // set initial timestamp
    gettimeofday(&(ctx->tv_init), NULL);

    if (ctx->neat_log_fd == NULL) {
        ctx->neat_log_fd = stderr;
    }

    neat_log(ctx, NEAT_LOG_INFO, "%s - opening logfile ...", __func__);

    return RETVAL_SUCCESS;
}

/*
 * Set the NEAT log level
 */
void
neat_log_level(struct neat_ctx *ctx, uint8_t level)
{
    switch (level) {
        case NEAT_LOG_OFF:
            ctx->log_level = NEAT_LOG_OFF;
            break;
        case NEAT_LOG_ERROR:
            ctx->log_level = NEAT_LOG_ERROR;
            break;
        case NEAT_LOG_WARNING:
            ctx->log_level = NEAT_LOG_WARNING;
            break;
        case NEAT_LOG_INFO:
            ctx->log_level = NEAT_LOG_INFO;
            break;
        case NEAT_LOG_DEBUG:
            ctx->log_level = NEAT_LOG_DEBUG;
            break;
        default:
            ctx->log_level = NEAT_LOG_DEBUG;
            fprintf(stderr, "%s - unknown log-level - using default\n", __func__);
            break;
    }
}

uint8_t
neat_log_file(struct neat_ctx *ctx, const char* file_name)
{
    // determine output fd
    if (file_name != NULL) {
        neat_log(ctx, NEAT_LOG_INFO, "%s - using logfile: %s", __func__, file_name);
        ctx->neat_log_fd = fopen(file_name, "w");

        if (ctx->neat_log_fd == NULL) {
            ctx->neat_log_fd = stderr;
            neat_log(ctx, NEAT_LOG_ERROR, "%s - could not open logfile, using stderr", __func__);
            return RETVAL_FAILURE;
        }

        return RETVAL_SUCCESS;
    } else {
        ctx->neat_log_fd = stderr;
        return RETVAL_SUCCESS;
    }
}

/*
 * Write log entry
 */
void
neat_log(struct neat_ctx *ctx, uint8_t level, const char* format, ...)
{

    struct timeval tv_now, tv_diff;
    // skip unwanted loglevels
    if (ctx->log_level < level) {
        return;
    }

    if (ctx->neat_log_fd == NULL) {
        fprintf(stderr, "neat_log_fd is NULL - neat_log_init() required!\n");
        return;
    }

    gettimeofday(&tv_now, NULL);

    tv_diff.tv_sec = tv_now.tv_sec - ctx->tv_init.tv_sec;

    if (ctx->tv_init.tv_usec <= tv_now.tv_usec) {
        tv_diff.tv_usec = tv_now.tv_usec - ctx->tv_init.tv_usec;
    } else {
        tv_diff.tv_sec -= 1;
        tv_diff.tv_usec = 1000000 + tv_now.tv_usec - ctx->tv_init.tv_usec;
    }

    if (isatty(fileno(ctx->neat_log_fd))) {
        switch (level) {
            case NEAT_LOG_ERROR:
                fprintf(ctx->neat_log_fd, RED);
                break;
            case NEAT_LOG_WARNING:
                fprintf(ctx->neat_log_fd, YEL);
                break;
            case NEAT_LOG_INFO:
                fprintf(ctx->neat_log_fd, GRN);
                break;
            case NEAT_LOG_DEBUG:
                //fprintf(neat_log_fd, WHT);
                break;
        }
    }

    fprintf(ctx->neat_log_fd, "[%4ld.%06ld]", (long)tv_diff.tv_sec, (long)tv_diff.tv_usec);

    switch (level) {
        case NEAT_LOG_ERROR:
            fprintf(ctx->neat_log_fd, "[ERR] ");
            break;
        case NEAT_LOG_WARNING:
            fprintf(ctx->neat_log_fd, "[WRN] ");
            break;
        case NEAT_LOG_INFO:
            fprintf(ctx->neat_log_fd, "[INF] ");
            break;
        case NEAT_LOG_DEBUG:
            fprintf(ctx->neat_log_fd, "[DBG] ");
            break;
    }

    va_list argptr;
    va_start(argptr, format);
    vfprintf(ctx->neat_log_fd, format, argptr);
    va_end(argptr);

    fprintf(ctx->neat_log_fd, "\n"); // xxx:ugly solution...

    if (isatty(fileno(ctx->neat_log_fd))) {
        fprintf(ctx->neat_log_fd, KNRM);
    }
}

/*
 * Write log entry for usrsctp
 */
void
neat_log_usrsctp(const char* format, ...)
{
#if 0
    // this neats to get a ctx from somwhere!
    if (ctx->neat_log_fd == NULL) {
        fprintf(stderr, "neat_log_fd is NULL - neat_log_init() required!\n");
        return;
    }

    fprintf(ctx->neat_log_fd, "[DBG] ");

    va_list argptr;
    va_start(argptr, format);
    vfprintf(ctx->neat_log_fd, format, argptr);
    va_end(argptr);
#endif
}

/*
 * Close logfile
 */
uint8_t
neat_log_close(struct neat_ctx *ctx)
{
    neat_log(ctx, NEAT_LOG_INFO, "%s - closing logfile ...", __func__);
    if (ctx->neat_log_fd != stderr) {
        if (fclose(ctx->neat_log_fd) == 0) {
            return RETVAL_SUCCESS;
        } else {
            return RETVAL_FAILURE;
        }
    }

    return RETVAL_SUCCESS;
}

#else // NEAT_LOG
uint8_t
neat_log_init(struct neat_ctx *ctx) {
    return RETVAL_SUCCESS;
}

void
neat_log_level(struct neat_ctx *ctx, uint8_t level) {
    return;
}

uint8_t
neat_log_file(struct neat_ctx *ctx, const char* file_name)
{
    return RETVAL_SUCCESS;
}

void
neat_log(struct neat_ctx *ctx, uint8_t level, const char* format, ...)
{
    return;
}

void
neat_log_usrsctp(const char* format, ...)
{
    return;
}

uint8_t
neat_log_close(struct neat_ctx *ctx)
{
    return RETVAL_SUCCESS;
}


#endif
