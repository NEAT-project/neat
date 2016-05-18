#ifndef NEAT_API_H
#define NEAT_API_H

#include "neat.h"
#include "neat_queue.h"

/*
 * OYSTEDAL:
 * A property request is made by the application to express a requirement/desire
 * for a certain property of the transport layer.
 *
 * For now, property requests are expressed as strings, contained in a linked list.
 * The list is not directly exposed to the application, so changing this
 * implementation into something more efficient should not be difficult
 *
 * TODO: How do we register properties to ensure that only valid/existing/used
 * properties are added to the lists?
 * ADD_NAMED_PROPERTY("TCP_REQUIRED")?
 * module-level init functions?
 *
 * TODO: Properties could theoretically be set on a per-context basis as well
 *
 * TODO: naming
 */

// A list of properties as requested by the application
struct neat_prop_request {
    char* property;

    LIST_ENTRY(neat_prop_request) property_list;
};
typedef struct neat_prop_request neat_prop_request;

LIST_HEAD(neat_prop_request_list, neat_prop_request);

// TODO: neat_{request,remove}_property should possibly return error codes

// neat_request_property adds a property request to the flow
void neat_request_property(struct neat_flow* flow, char* property);

// neat_remove_property removes a property request from the flow
void neat_remove_property(struct neat_flow* flow, char* property);

void neat_remove_all_properties(struct neat_flow* flow);

// neat_check_property tests to see if a given property request is present
int neat_check_property(struct neat_flow* flow, char* property);

// int neat_check_property(struct neat_ctx* ctx, char* property);

#endif
