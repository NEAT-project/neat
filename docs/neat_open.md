# neat_open

Open a neat flow and connect it to a given remote name and port.

### Syntax
```c
neat_error_code neat_open(struct neat_ctx *ctx,
                          struct neat_flow *flow,
                          const char *name,
                          uint16_t port,
                          struct neat_tlv optional[],
                          unsigned int opt_count);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to a NEAT flow.
- **name**: The remote name to connect to.
- **port**: The remote port to connect to.
- **optional**: An array containing optional parameters.
- **opt_count**: The length of the array containing optional parameters.

### Optional parameters

- **NEAT_TAG_STREAM_COUNT** (integer): The number of streams to open, for protocols that
supports multistreaming
- **NEAT_TAG_FLOW_GROUP** (integer): The group ID that this flow belongs to. For use with
coupled congestion control.
- **NEAT_TAG_PRIORITY** (float): The priority of this flow relative to the other flows. Must be between 0.1 and 1.0.
- **NEAT_TAG_CC_ALGORITHM** (string): The congestion control algorithm to use for
this flow.

### Return values

- Returns `NEAT_OK` if the flow opened successfully.
- Returns `NEAT_ERROR_OUT_OF_MEMORY` if the function was unable to allocate enough memory.

### Remarks

Callbacks can be specified with `neat_set_operations`. The `on_connected`
callback will be invoked if the connection established successfully. The
`on_error` callback will be invoked if NEAT is unable to connect to the remote
endpoint.

### Examples

```c
neat_open(ctx, flow, "bsd10.fh-muenster.de", 80, NULL, 0);
```

### See also

- [neat_read](neat_read.md)
- [Optional arguments](optargs.md)
