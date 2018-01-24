#ifndef NEAT_LOG_H
#define NEAT_LOG_H

#include <stdint.h>
#include "neat.h"

uint8_t nt_log_init(struct neat_ctx *ctx);
void nt_log(struct neat_ctx *ctx, uint8_t level, const char* format, ...);
void neat_log_usrsctp(const char* format, ...);
uint8_t nt_log_close(struct neat_ctx *ctx);

#endif
