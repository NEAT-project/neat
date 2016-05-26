#include <stdlib.h>
#include <string.h>

#include "neat.h"
#include "neat_api.h"
#include "neat_internal.h"

void neat_request_property(neat_flow* flow, char* property) {
    struct neat_prop_request* prop = NULL;
    LIST_FOREACH(prop, flow->property_requests, property_list) {
        if (strcmp(prop->property, property) == 0) {
            return;
        }
    }

    prop = malloc(sizeof(*prop));
    prop->property = strdup(property);

    LIST_INSERT_HEAD(flow->property_requests, prop, property_list);
}

void neat_remove_property(neat_flow* flow, char* property) {
    struct neat_prop_request* prop = NULL;
    LIST_FOREACH(prop, flow->property_requests, property_list) {
        if (strcmp(prop->property, property) == 0) {
            LIST_REMOVE(prop, property_list);
            free(prop->property);
            free(prop);
            return;

        }
    }
}

void neat_remove_all_properties(neat_flow* flow) {
    while (!LIST_EMPTY(flow->property_requests)) {
        struct neat_prop_request* prop = LIST_FIRST(flow->property_requests); 
        LIST_REMOVE(prop, property_list);
        free(prop->property);
        free(prop);
    }
}

int neat_check_property(neat_flow* flow, char* property) {
    struct neat_prop_request* prop = NULL;
    LIST_FOREACH(prop, flow->property_requests, property_list) {
        if (strcmp(prop->property, property) == 0) {
            return 1;
        }
    }

    return 0;
}
