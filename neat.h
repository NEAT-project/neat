#ifndef NEAT_H
#define NEAT_H

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

// this is the public API.. todo organize and explain

struct neat_ctx;

//Set up and allocate context
struct neat_ctx *neat_init_ctx();

//Start the event loop, currently uses libuv. User wants to start some action
//(like resolve) before this is called
void neat_start_event_loop(struct neat_ctx *nc);

//Free memory used by context
void neat_free_ctx(struct neat_ctx *nc);

// todo neat_stop_event_loop



#endif
