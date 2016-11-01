# neat_abort

Abort this flow and free all associated data.

### Syntax

```c
neat_error_code neat_abort(struct neat_ctx *ctx,
                           struct neat_flow *flow);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to the NEAT flow to be aborted.

### Return values

- Returns `NEAT_OK`.

### Remarks

Calls `neat_close` internally.

### Examples

None.

### See also

- [neat_shutdown](neat_shutdown.md)
- [neat_close](neat_close.md)
