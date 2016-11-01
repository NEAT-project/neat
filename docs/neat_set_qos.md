# neat_set_qos

Set the Quality-of-Service class for this flow.

### Syntax

```c
neat_error_code neat_set_qos(struct neat_ctx *ctx,
                             struct neat_flow *flow,
                             uint8_t qos);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to a NEAT flow.
- **qos**: The QoS class to use for this flow.

### Return values

- Returns `NEAT_OK` if the QoS class was set successfully.
- Returns `NEAT_ERROR_UNABLE` if NEAT was not able to set the requested QoS class.

### Remarks

None.

### Examples

None.

### See also

None.
