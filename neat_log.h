#ifndef NEAT_LOG_H
#define NEAT_LOG_H

#include <stdint.h>
#include "neat.h"

uint8_t neat_log_init();
void neat_log(uint8_t level, const char* format, ...);
void neat_log_usrsctp(const char* format, ...);
uint8_t neat_log_close();

#endif
