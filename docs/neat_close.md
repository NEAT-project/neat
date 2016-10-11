# neat_close

Close this flow and free all associated data.

### Syntax

```c
neat_error_code neat_close(struct neat_ctx *ctx,
                           struct neat_flow *flow);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to the NEAT flow to be closed.

### Return values

- Returns `NEAT_OK`.

### Remarks

None.

### Examples

None.

### See also

- [neat_shutdown](neat_shutdown.md)
