# neat_accept

Listen to incoming connections on a given port on one or more protocols.

### Syntax
```c
neat_error_code neat_accept(struct neat_ctx *ctx,
                            struct neat_flow *flow,
                            uint16_t port,
                            struct neat_tlv optional[],
                            unsigned int opt_count);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to a NEAT flow.
- **port**: The local port to listen for incoming connections on.
- **optional**: An array containing optional parameters.
- **opt_count**: The length of the array containing optional parameters.

### Optional parameters

- **NEAT_TAG_STREAM_COUNT** (integer): The number of streams to accept, for protocols that
supports multistreaming.

### Return values

- Returns `NEAT_OK` if NEAT is listening for incoming connections on at least one protocol.
- Returns `NEAT_ERROR_UNABLE` if there is no appropriate protocol available for the flow properties that was specified.
- Returns `NEAT_ERROR_BAD_ARGUMENT` if **flow** is pointing to a flow that is already opened or listening for incoming connections.
- Returns `NEAT_ERROR_BAD_ARGUMENT` if **NEAT_TAG_STREAM_COUNT** is less than 1.
- Returns `NEAT_ERROR_OUT_OF_MEMORY` if the function was unable to allocate enough memory.

### Remarks

Callbacks can be specified with `neat_set_operations`. The `on_connected`
callback will be invoked if the connection established successfully. The
`on_error` callback will be invoked if NEAT is unable to connect to the remote
endpoint.

Which protocols to listen to is determined by the flow properties.

### Examples

```c
neat_accept(ctx, flow, 8080, NULL, 0);
```

### See also

- [neat_open](neat_open.md)
- [Optional arguments](optargs.md)
