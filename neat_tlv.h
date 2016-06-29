#ifndef NEAT_TLV_INCLUDE
#define NEAT_TLV_INCLUDE

#include "neat.h"
#include "neat_tags.h"

#define NEAT_TLV_LIMIT 32

typedef enum {
    TYPE_INT = 1,
    TYPE_UINT,
    TYPE_FLOAT,
    TYPE_STRING,
    TYPE_BOOL,
} neat_value_type;

struct tlv {
    neat_tag tag;
    neat_value_type type;
    void* data;
};

struct neat_tlv {
    size_t count;
    struct tlv data[NEAT_TLV_LIMIT];
};

#define CREATE_OPT_ARGS(name) \
    struct neat_tlv name; \
    name.count = 0;

#define NEAT_OPT_INT(name, tagname, value) \
    int32_t __ ## name ## _ ## tagname = value; \
        do { \
            if (name.count >= NEAT_TLV_LIMIT) { \
                    neat_log(NEAT_LOG_DEBUG, "Exceeded TLV limit"); \
                    break; \
            } \
            size_t id = name.count++; \
            name.data[id].tag = tagname; \
            name.data[id].type = TYPE_INT; \
            name.data[id].data = (void*)&__ ## name ## _ ## tagname; \
        } while(0);

#define NEAT_OPTARG_PARAM struct neat_tlv* __optargs

#define READ_OPT(varname, tagname, vartype, defaultval, valuetype) \
    uint8_t __ ## varname ## _is_present = 0; \
    vartype varname = defaultval; \
    do { \
        if (__optargs == NULL) \
            break;\
        for (size_t i = 0; i < __optargs->count; ++i) { \
            if (__optargs->data[i].tag == tagname) { \
                if (__optargs->data[i].type != TYPE_INT) { \
                    printf("Invalid type for optional argument " #tagname "," \
                           " (expected type " #vartype ")\n");\
                    break; \
                } \
                varname = *(vartype*)(__optargs->data[i].data); \
                __ ## varname ## _is_present = 1; \
            } \
        } \
    } while (0);

#define READ_OPT_INT(varname, tagname, defaultvalue) \
    READ_OPT(varname, tagname, int32_t, defaultvalue, TYPE_BOOL)

#define READ_OPT_BOOL(varname, tagname, defaultvalue) \
    READ_OPT(varname, tagname, uint8_t, defaultvalue, TYPE_BOOL)

#define READ_OPT_UINT(varname, tagname, defaultvalue) \
    READ_OPT(varname, tagname, uint32_t, defaultvalue, TYPE_UINT)

#define READ_OPT_FLOAT(varname, tagname, defaultvalue) \
    READ_OPT(varname, tagname, float, defaultvalue, TYPE_FLOAT)

#define READ_OPT_STRING(varname, tagname, defaultvalue) \
    READ_OPT(varname, tagname, char*, defaultvalue, TYPE_STRING)

#define HAS_OPTARG(varname) (__ ## varname ## _is_present == 1)

// Free memory allocated for optional return values
#define FREE_OPT_RETURN(name) \
    do { \
        for (size_t i = 0; i < name->count; ++i) { \
            free(name->data[i]); \
        } \
    } while (0);

#endif /* ifndef NEAT_TLV_INCLUDE */

