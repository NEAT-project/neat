#ifndef NEAT_RESOLVE_H
#define NEAT_RESOLVE_H

struct neat_event_cb;

struct neat_resolver {
    //The reason we need three of these is that as of now, a neat_event_cb
    //struct can only be part of one list. This is a future optimization, if we
    //decide that it is a problem
    struct neat_event_cb newaddr_cb;
    struct neat_event_cb updateaddr_cb;
    struct neat_event_cb deladdr_cb;
};

#endif
