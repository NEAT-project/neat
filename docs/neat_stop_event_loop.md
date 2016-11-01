# neat_stop_event_loop

Stops the internal NEAT event loop.

### Syntax

```c
int neat_stop_event_loop(struct neat_ctx *ctx);
```

### Parameters

- **ctx**: Pointer to a NEAT context.

### Return values

None.

### Remarks

Once called, no further events will be processed and no callbacks will be called
until `neat_start_event_loop` is called again.

### Examples

None.

### See also

- [neat_start_event_loop](neat_start_event_loop.md)
