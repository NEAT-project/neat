# neat_set_ecn

Set the Explicit Congestion Notification value for this flow.

### Syntax

```c
neat_error_code neat_set_ecn(struct neat_ctx *ctx,
                             struct neat_flow *flow,
                             uint8_t ecn);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to a NEAT flow.
- **ecn**: The ECN value to use for this flow.

### Return values

- Returns `NEAT_OK` if the QoS class was set successfully.
- Returns `NEAT_ERROR_UNABLE` if NEAT was not able to set the requested ECN value.

### Remarks

None.

### Examples

None.

### See also

None.
