#ifndef NEAT_JSON_HELPERS_INCLUDE_H
#define NEAT_JSON_HELPERS_INCLUDE_H

#include "neat_internal.h"
#include "neat_json_helpers.h"

// #define NEAT_KEYVAL(key,value) ("{ \"" #key "\": " #value" }")

void nt_find_enabled_stacks(json_t *json, neat_protocol_stack_type *stacks,
                         size_t *stack_count, int *precedences);

json_t* get_property(json_t *json, const char *key, json_type expected_type);

neat_protocol_stack_type string_to_stack(const char *str);
const char* stack_to_string(neat_protocol_stack_type stack);

#endif /* ifndef NEAT_JSON_HELPERS_INCLUDE_H */
