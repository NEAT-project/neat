# neat_set_property

Set the properties of a NEAT flow.

### Syntax

```c
neat_error_code neat_set_property(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    const char *properties);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to a NEAT flow.
- **properties**: Pointer to a JSON-encoded string containing the flow properties.

### Return values

- Returns `NEAT_OK` if the properties were set successfully.
- Returns `NEAT_ERROR_BAD_ARGUMENT` if the JSON-encoded string is malformed.

### Remarks

Properties are applied when a flow connects.

### Examples

None.

### See also

None.
