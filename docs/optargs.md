# Optional arguments

Some of the functions in the NEAT API, such as `neat_open`, `neat_read` and
`neat_write`, take optional arguments. These are sometimes used to pass
optional arguments to functions, and sometimes used to return additional
values from the function. Optional arguments are passed as an array of the
struct `neat_tlv` and an integer specifying the length of this array.
`neat_tlv` is defined as follows:

```c
struct neat_tlv {
    neat_tlv_tag  tag;
    neat_tlv_type type;

    union {
        int   integer;
        char *string;
        float real;
    } value;
};
```

An optional argument takes the form of a tag name, a type, and a value of
either a string, integer or a floating point number. The tag specifies which
optional argument the value belongs to, and the type asserts the type of the
value passed as this argument. An error will be raised of the type is
different than what the function expects.

You may either work with this struct directly, or you may use the preprocessor
macros explained later in this document.

### Specifying no optional arguments

To specify no optional arguments, simply pass `NULL` as the `optargs` parameter
and `0` as the `opt_count` parameter of the function.

### Optional argument macros

- **NEAT_OPTARGS_DECLARE(max)** - Declare the necessary variables to use the
  rest of these macros. Allocates (on the stack) an array of length *max* and
  an integer for storing the number of optional arguments specified.
  `NEAT_OPTARGS_MAX` may be used as the default array size.
- **NEAT_OPTARGS_INIT()** - Initializes the variables declared by
  `NEAT_OPTARGS_DECLARE`. May also be used to reset the (number of) optional
arguments back to 0.
- **NEAT_OPTARG_INT(tag,value)** - Specify the tag and the value of an
  optional argument that takes an integer.
- **NEAT_OPTARG_FLOAT(tag,value)** - Specify the tag and the value of an
  optional argument that takes a floating point number.
- **NEAT_OPTARG_STRING(tag,value)** - Specify the tag and the value of an
  optional argument that takes a string.
- **NEAT_OPTARGS** - Represents the array of optional arguments. Specify this
  macro as the `optarg` parameter.
- **NEAT_OPTARG_COUNT** - Stores the number of the optional arguments
  specified so far with `NEAT_OPTARG_INT`, `NEAT_OPTARG_FLOAT` or
  `NEAT_OPTARG_STRING`. This count is reset by `NEAT_OPTARGS_INIT()`. Specify
  this macro as the `opt_count` argument.

### Optional argument tags

- **NEAT_TAG_STREAM_ID** (integer) - Specifies the ID of the stream which the data should
  be written to, or which stream the data was read from.
- **NEAT_TAG_STREAM_COUNT** (integer) - Specifies the number of stream to create. Only used
  with protocols that support multiple streams.
- **NEAT_TAG_FLOW_GROUP** (int) - Specifies the flow group this flow belongs to.
- **NEAT_TAG_PRIORITY** (float) - Specifies the priority of this flow relative to other
  flows in the flow group.
- **NEAT_TAG_CC_ALGORITHM** (string) - Speficies the name of the (TCP) congestion control
  algorithm that will be used by this flow. A system default will be used if the specified
  algorithm is not available.

Currently unused tags:
- **NEAT_TAG_LOCAL_NAME**
- **NEAT_TAG_SERVICE_NAME**
- **NEAT_TAG_CONTEXT**
- **NEAT_TAG_PARTIAL_RELIABILITY_METHOD**
- **NEAT_TAG_PARTIAL_RELIABILITY_VALUE**
- **NEAT_TAG_PARTIAL_MESSAGE_RECEIVED**
- **NEAT_TAG_PARTIAL_SEQNUM**
- **NEAT_TAG_UNORDERED**
- **NEAT_TAG_UNORDERED_SEQNUM**
- **NEAT_TAG_DESTINATION_IP_ADDRESS**

### Examples

```c
    NEAT_OPTARGS_DECLARE(NEAT_OPTARGS_MAX);
    NEAT_OPTARGS_INIT();
    NEAT_OPTARG_INT(NEAT_TAG_STREAM_COUNT, 5);
    neat_open(ctx, flow, "127.0.0.1", 8000, NEAT_OPTARGS, NEAT_OPTARGS_COUNT);
```
