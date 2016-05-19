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

void neat_set_property_bool(neat_flow* flow, char* property, int value)
{
    struct neat_prop_request* prop = NULL;
    LIST_FOREACH(prop, flow->property_requests, property_list) {
        if (strcmp(prop->property, property) == 0) {
            prop->type = TYPE_BOOL;
            prop->data.int_value = value == 0 ? 0 : 1;
            return;
        }
    }

    prop = malloc(sizeof(*prop));
    prop->property = strdup(property);
    prop->type = TYPE_BOOL;
    prop->data.int_value = value == 0 ? 0 : 1;

    LIST_INSERT_HEAD(flow->property_requests, prop, property_list);
}

neat_error_code neat_get_property_bool(neat_flow* flow, char* property, int* value) {
    struct neat_prop_request* prop = NULL;
    LIST_FOREACH(prop, flow->property_requests, property_list) {
        if (strcmp(prop->property, property) == 0) {
            if (prop->type != TYPE_BOOL)
                return NEAT_ERROR_BAD_ARGUMENT;

            *value = prop->data.int_value;
            return NEAT_OK;
        }
    }

    return NEAT_ERROR_BAD_ARGUMENT;
}

void neat_set_property_int(neat_flow* flow, char* property, int value)
{
    struct neat_prop_request* prop = NULL;
    LIST_FOREACH(prop, flow->property_requests, property_list) {
        if (strcmp(prop->property, property) == 0) {
            prop->type = TYPE_INT;
            prop->data.int_value = value;
            return;
        }
    }

    prop = malloc(sizeof(*prop));
    prop->property = strdup(property);
    prop->type = TYPE_INT;
    prop->data.int_value = value;

    LIST_INSERT_HEAD(flow->property_requests, prop, property_list);
}

neat_error_code neat_get_property_int(neat_flow* flow, char* property, int* value) {
    struct neat_prop_request* prop = NULL;
    LIST_FOREACH(prop, flow->property_requests, property_list) {
        if (strcmp(prop->property, property) == 0) {
            *value = prop->data.int_value;
            return NEAT_OK;
        }
    }

    return NEAT_ERROR_BAD_ARGUMENT;
}

void neat_set_property_float(neat_flow* flow, char* property, float value)
{
    struct neat_prop_request* prop = NULL;
    LIST_FOREACH(prop, flow->property_requests, property_list) {
        if (strcmp(prop->property, property) == 0) {
            prop->type = TYPE_FLOAT;
            prop->data.float_value = value;
            return;
        }
    }

    prop = malloc(sizeof(*prop));
    prop->property = strdup(property);
    prop->type = TYPE_FLOAT;
    prop->data.int_value = value;

    LIST_INSERT_HEAD(flow->property_requests, prop, property_list);
}

void neat_set_property_string(neat_flow* flow, char* property, const char* value)
{
    struct neat_prop_request* prop = NULL;
    LIST_FOREACH(prop, flow->property_requests, property_list) {
        if (strcmp(prop->property, property) == 0) {
            prop->type = TYPE_STRING;
            prop->data.string_value = strdup(value);
            return;
        }
    }

    prop = malloc(sizeof(*prop));
    prop->property = strdup(property);
    prop->type = TYPE_STRING;
    prop->data.string_value = strdup(value);

    LIST_INSERT_HEAD(flow->property_requests, prop, property_list);
}

neat_error_code neat_get_property_string(neat_flow* flow, char* property, char** value) {
    struct neat_prop_request* prop = NULL;
    LIST_FOREACH(prop, flow->property_requests, property_list) {
        if (strcmp(prop->property, property) == 0) {
            if (prop->type != TYPE_STRING)
                return NEAT_ERROR_BAD_ARGUMENT;

            *value = strdup(prop->data.string_value);
            return NEAT_OK;
        }
    }

    return NEAT_ERROR_BAD_ARGUMENT;
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

// Initialize the property set to the defaults
void neat_properties_init(neat_flow* flow) {
    LIST_INIT(flow->property_requests);

    neat_set_property_bool(flow, "seamless_handover", 0);
    neat_set_property_bool(flow, "optimise_continuous_connectivity", 0);
    neat_set_property_int(flow, "metadata_privacy", 0);
    neat_set_property_bool(flow, "disable_dynamic_enhancement", 0);
    neat_set_property_bool(flow, "low_latency_desired", 0);
    neat_set_property_int(flow, "flow_group", 0);
    neat_set_property_float(flow, "flow_priority", 0.5f);
    neat_set_property_float(flow, "dscp_value", 0.5f);

    neat_set_property_bool(flow, "optional_sequrity", 0);
    neat_set_property_bool(flow, "required_sequrity", 0);
    neat_set_property_bool(flow, "message", 0);
    neat_set_property_bool(flow, "ipv4_required", 0);
    neat_set_property_bool(flow, "ipv4_banned", 0);
    neat_set_property_bool(flow, "ipv6_required", 0);
    neat_set_property_bool(flow, "ipv6_banned", 0);
    neat_set_property_bool(flow, "sctp_required", 0);
    neat_set_property_bool(flow, "sctp_banned", 0);
    neat_set_property_bool(flow, "tcp_required", 0);
    neat_set_property_bool(flow, "tcp_banned", 0);
    neat_set_property_bool(flow, "udp_required", 0);
    neat_set_property_bool(flow, "udp_banned", 0);
    neat_set_property_bool(flow, "udplite_required", 0);
    neat_set_property_bool(flow, "udplite_banned", 0);
    neat_set_property_bool(flow, "congestion_control_required", 0);
    neat_set_property_bool(flow, "congestion_control_banned", 0);
    neat_set_property_bool(flow, "retransmissions_required", 0);
    neat_set_property_bool(flow, "retransmissions_banned", 0);
}
