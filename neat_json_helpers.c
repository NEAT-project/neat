#include "neat_internal.h"
#include "neat_json_helpers.h"

#include <assert.h>
#include <string.h>

#define BANNED_ENABLED 0

#define NEAT_TRANSPORT_PROPERTY(name, propname, protonum)		\
{									\
    #name,								\
    protonum							\
}

#define NEAT_TRANSPORT(name) \
{ \
    #name, \
    NEAT_STACK_ ## name \
}

struct neat_transport_property {
    const char *name;
    neat_protocol_stack_type stack;
};

static struct neat_transport_property neat_transports[] = {
    NEAT_TRANSPORT(TCP),
    NEAT_TRANSPORT(SCTP),
    NEAT_TRANSPORT(UDP),
    {"UDPlite", NEAT_STACK_UDPLITE},
    {"UDPLite", NEAT_STACK_UDPLITE},
    {"UDP-Lite", NEAT_STACK_UDPLITE},
    {"UDP-lite", NEAT_STACK_UDPLITE},
    {"UDPLITE", NEAT_STACK_UDPLITE},
    {"SCTP/UDP", NEAT_STACK_SCTP_UDP},
};

neat_protocol_stack_type
string_to_stack(const char *str)
{
    for (size_t i = 0; i < sizeof(neat_transports) / sizeof(*neat_transports); ++i) {
        if (strcmp(str, neat_transports[i].name) == 0) {
            return neat_transports[i].stack;
        }
    }

    return 0;
}


/*
 * Parse the json structure to discover which protocols are enabled.
 *
 * There are four modes:
 * 1. One and only one protocol with precendece == 2
 * 2. Some protocols with precendece == 2, some protocols with precedence == 1
 * 3. Multiple protocols with precedence == 1
 * 4. All protocols listed are banned
 *
 * A pointer to an array of ints must be given for mode 2. This mode is intended
 * for listening sockets only. Errors will be reported when a protocol has
 * precedence == 2, otherwise the error will be silently ignored. In mode 4,
 * all protocols will be assumed to have precedence 1.
 *
 * TODO: Contemplate whether this can be written better somehow.
 */
void
neat_find_enabled_stacks(json_t *json, neat_protocol_stack_type *stacks,
                    size_t *stack_count, int *precedences)
{
    json_t *transports, *transport;
    size_t i;
    neat_protocol_stack_type *stack_ptr = stacks;
    size_t count = 0;
#if BANNED_ENABLED
    neat_protocol_stack_type banned[NEAT_STACK_MAX_NUM];
    neat_protocol_stack_type *banned_ptr = banned;
    size_t ban_count = 0;
#endif

    assert(json);
    assert(stacks && stack_count);
    // assert(*stack_count >= NEAT_MAX_NUM_PROTO);

    transports = json_object_get(json, "transport");

    json_array_foreach(transports, i, transport) {
        int precedence = json_integer_value(json_object_get(transport, "precedence"));
        const char* value;
        json_t* val;
        neat_protocol_stack_type stack;

        val = json_object_get(transport, "value");
        assert(val);
        assert(json_typeof(val) == JSON_STRING);
        value = json_string_value(val);

        if (precedence == 2) {
            // Don't specify more than one transport if you have precedence == 2,
            // unless it's for listening sockets
            assert(json_array_size(transports) == 1 || precedences);

            if ((stack = string_to_stack(value)) != 0) {
                *stacks = stack;
                count++;

                if (precedences) {
                    *(precedences++) = precedence;
                } else {
                    *stack_count = count;
                    return;
                }

            } else {
                neat_log(NEAT_LOG_DEBUG, "Unknown transport %s", value);
                *stack_count = 0;
            }

            if (!precedences)
                return;
        } else if (precedence == 1) {
#if BANNED_ENABLED
            int b;

            val = json_object_get(transport, "banned");
            b = json_boolean_value(val);

            if ((stack = string_to_stack(value)) != 0) {
                if (val && b) {
                    *(banned_ptr++) = stack;
                    ban_count++;
                    continue;
                } else {
                    *(stack_ptr++) = stack;
                    count++;
                    if (precedences) {
                        *(precedences++) = precedence;
                    }
                }
            } else {
                neat_log(NEAT_LOG_DEBUG, "Unknown transport %s", value);
            }
#else
            if ((stack = string_to_stack(value)) != 0) {
                *(stack_ptr++) = stack;
                count++;
                if (precedences) {
                    *(precedences++) = precedence;
                }
            } else {
                neat_log(NEAT_LOG_DEBUG, "Unknown transport %s", value);
            }
#endif
        } else {
            neat_log(NEAT_LOG_ERROR, "Invalid precedence %d in JSON", precedence);
            *stack_count = 0;
            return;
        }
    }

#if BANNED_ENABLED
    // If only banned protocols are specified
    if (ban_count > 0 && count == 0) {
        // Add all known protocols, except those that are banned...
        for (size_t i = 0; i < sizeof(neat_transports) / sizeof(*neat_transports); ++i) {
            for (size_t j = 0; j < ban_count; ++j) {
                if (neat_transports[i].stack == banned[j])
                    goto skip;
            }

            *(stack_ptr++) = neat_transports[i].stack;
            count++;
            if (precedences)
                *(precedences++) = 1;
skip:
            continue;
        }
    }
#endif

    *stack_count = count;
}

json_t*
get_property(json_t *json, const char *key, json_type expected_type)
{
    json_t *obj = json_object_get(json, key);

    if (!obj) {
        neat_log(NEAT_LOG_DEBUG, "Unable to find property with key \"%s\"", key);
        return NULL;
    }

    obj = json_object_get(obj, "value");
    if (!obj) {
        neat_log(NEAT_LOG_DEBUG, "Object with key \"%s\" is missing value key");
        return NULL;
    }

    if (json_typeof(obj) != expected_type) {
        const char *typename = NULL;
        switch (json_typeof(obj)) {
        case JSON_OBJECT:
            typename = "object";
            break;
        case JSON_ARRAY:
            typename = "array";
            break;
        case JSON_INTEGER:
            typename = "integer";
            break;
        case JSON_STRING:
            typename = "string";
            break;
        case JSON_REAL:
            typename = "real";
            break;
        case JSON_NULL:
            typename = "null";
            break;
        case JSON_TRUE:
        case JSON_FALSE:
            typename = "bool";
            break;
        }

        neat_log(NEAT_LOG_DEBUG, "Key \"%s\" had unexpected type", key, typename);
        return NULL;
    }

    return obj;
}
