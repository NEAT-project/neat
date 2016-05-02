#ifndef NEAT_LOG_H
#define NEAT_LOG_H

#include <stdint.h>

#define NEAT_LOG_OFF 0
#define NEAT_LOG_ERROR 1
#define NEAT_LOG_WARNING 2
#define NEAT_LOG_INFO 3
#define NEAT_LOG_DEBUG 4

#define NEAT_LOG_STDERR 0

uint8_t neat_log_init();
void neat_log(uint8_t level, const char* format, ...);
void neat_log_usrsctp(const char* format, ...);
uint8_t neat_log_close();


#endif
