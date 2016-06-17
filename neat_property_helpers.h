#ifndef NEAT_PROPERTY_HELPERS_H
#define NEAT_PROPERTY_HELPERS_H

#include <stdint.h>
#include "neat_internal.h"

uint8_t neat_property_translate_protocols(uint64_t propertyMask,
        neat_protocol_stack_type stacks[]);

#endif
