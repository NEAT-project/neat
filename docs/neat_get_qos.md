# neat_get_qos

Get the Quality-of-Service class for this flow.

### Syntax

```c
neat_error_code neat_get_qos(struct neat_ctx *ctx,
                             struct neat_flow *flow)
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to a NEAT flow.

### Return values

- Returns the used DiffServ Code Point(DSCP) used signal QoS for this flow.

### Remarks

None.

### Examples

None.

### See also

None.
