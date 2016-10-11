# neat_get_backend_fd

Stops the internal NEAT event loop.

### Syntax

```c
int neat_get_backend_fd(struct neat_ctx *ctx);
```

### Parameters

- **ctx**: Pointer to a NEAT context.

### Return values

Returns the file descriptor of the event loop used internally by NEAT. May be
polled to check for any new events.

### Remarks

Note that embedding this event loop inside another event loop may not be
supported on all systems.

### Examples

None.

### See also

- [neat_start_event_loop](neat_start_event_loop.md)

