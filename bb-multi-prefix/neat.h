#ifndef NEAT_H
#define NEAT_H

#include <uv.h>

#define NEAT_CTX \
    uv_loop_t *loop

struct neat_ctx {
    NEAT_CTX;
};

//Allocate a neat context struct. Size of struct will depend on platform
//TODO: Support not forcing users to use the heap. This will involve exporting
//the internal variables
struct neat_ctx *neat_alloc_ctx();

//Call the internal intiialize method to set up the context
uint8_t neat_init_ctx(struct neat_ctx *nc);

//Start the event loop, currently uses libuv. User wants to start some action
//(like resolve) before this is called
void neat_start_event_loop(struct neat_ctx *nc);

//Free memory used by context
void neat_free_ctx(struct neat_ctx *nc);

//TODO: Add other parameters later
uint8_t neat_getaddrinfo(struct neat_ctx *nc, const char *service);

#endif
