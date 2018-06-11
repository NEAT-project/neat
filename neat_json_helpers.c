#include "neat_internal.h"
#include "neat_json_helpers.h"

#include <assert.h>
#include <string.h>

#define BANNED_ENABLED 0

#define NEAT_TRANSPORT_PROPERTY(name, propname, protonum)        \
{                                    \
    #name,                                \
    protonum                            \
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
    NEAT_TRANSPORT(MPTCP),
    NEAT_TRANSPORT(SCTP),
    NEAT_TRANSPORT(UDP),
    {"UDPlite", NEAT_STACK_UDPLITE},
    {"UDPLite", NEAT_STACK_UDPLITE},
    {"UDP-Lite", NEAT_STACK_UDPLITE},
    {"UDP-lite", NEAT_STACK_UDPLITE},
    {"UDPLITE", NEAT_STACK_UDPLITE},
    {"SCTP/UDP", NEAT_STACK_SCTP_UDP},
    {"WEBRTC", NEAT_STACK_WEBRTC}
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

const char*
stack_to_string(neat_protocol_stack_type stack)
{
    for (size_t i = 0; i < sizeof(neat_transports) / sizeof(*neat_transports); ++i) {
        if (stack == neat_transports[i].stack) {
            return neat_transports[i].name;
        }
    }

    return NULL;
}

/*
 * Parse the json structure to discover which protocols are enabled.
 *
 * TODO: Contemplate whether this can be written better somehow.
 */
void
nt_find_enabled_stacks(json_t *json, neat_protocol_stack_type *stacks,
                    size_t *stack_count, int *precedences)
{
    json_t *transports, *transport;
    json_error_t error;
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
    if (transports == NULL) {
      // The transport property is missing so we do not have a transport type.
      // This should not happen if the Policy Manager is running. We'll use the
      // following as a fallback:
      const char *fallback_transports = "{\"value\": [\"TCP\", \"SCTP\", \"MPTCP\"]}";
      transports = json_loads(fallback_transports, 0, &error);

      nt_log(NULL, NEAT_LOG_DEBUG, "No transport property defined. Using fallback!");
    }

    if (json_is_object(transports)) {
        // new properties format
        int precedence = json_integer_value(json_object_get(transports, "precedence"));
        const char* value;
        json_t* val;

        val = json_object_get(transports, "value");
        assert(val);

        // transport _values_ are either a single string e.g. {"value": "TCP"},
        // or a dict of supported transport protocols e.g. {"value": ["TCP", "SCTP", "MPTCP"]}
        if (json_typeof(val) == JSON_STRING) {
            neat_protocol_stack_type stack;
            value = json_string_value(val);
            nt_log(NULL, NEAT_LOG_DEBUG, "Transport: %s", value);
            if ((stack = string_to_stack(value)) != 0) {
                *(stack_ptr++) = stack;
                count++;
                if (precedences) {
                    *(precedences++) = precedence;
                }
            } else {
                nt_log(NULL, NEAT_LOG_DEBUG, "Unknown transport %s", value);
                *stack_count = 0;
            }
        } else if (json_typeof(val) == JSON_ARRAY){
            json_array_foreach(val, i, transport){
                neat_protocol_stack_type stack;
                value = json_string_value(transport);
                nt_log(NULL, NEAT_LOG_DEBUG, "Transport: %s", value);
                if ((stack = string_to_stack(value)) != 0) {
                    *(stack_ptr++) = stack;
                    count++;
                    if (precedences) {
                        *(precedences++) = precedence;
                    }
                } else {
                  nt_log(NULL, NEAT_LOG_DEBUG, "Unknown transport %s", value);
                }
            }
        }
    } else  {
        fprintf(stderr, "ERROR: Invalid property format\n");
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
        nt_log(NULL, NEAT_LOG_DEBUG, "Unable to find property with key \"%s\"", key);
        return NULL;
    }

    obj = json_object_get(obj, "value");
    if (!obj) {
        nt_log(NULL, NEAT_LOG_DEBUG, "Object with key \"%s\" is missing value key");
        return NULL;
    }

    if (json_typeof(obj) != expected_type) {
#if 0
        // no ctx, can't log!
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

        nt_log(ctx, NEAT_LOG_DEBUG, "Key \"%s\" had unexpected type: \"%s\"", key, typename);
#endif
        return NULL;
    }

    return obj;
}
