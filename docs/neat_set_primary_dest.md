# neat_set_primary_dest

For multihomed flows, set the primary destination address.

### Syntax

```c
neat_error_code neat_set_primary_dest(struct neat_ctx *ctx,
                                      struct neat_flow *flow,
                                      const char* address);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to a NEAT flow.
- **address**: The remote address to use as the primary destination address.

### Return values

- Returns `NEAT_OK` if the primary destination address was set successfully.
- Returns `NEAT_ERROR_UNABLE` if the flow is not using SCTP as the transport protocol.
- Returns `NEAT_ERROR_BAD_ARGUMENT` if the provided address is not a literal IP address.

### Remarks

Currently only available for SCTP.

### Examples

None.

### See also

None.
