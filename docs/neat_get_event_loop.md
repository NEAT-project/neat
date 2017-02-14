# neat_get_event_loop

Return the internal NEAT event loop pointer.

### Syntax

```c
uv_loop_t neat_get_event_loop(struct neat_ctx *ctx);
```

### Parameters

- **ctx**: Pointer to a NEAT context.

### Return values

Returns the the event loop used internally by NEAT.

### Examples

None.

### See also

- [neat_start_event_loop](neat_start_event_loop.md)
