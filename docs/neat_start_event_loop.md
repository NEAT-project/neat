# neat_start_event_loop

Starts the internal event loop within NEAT.

### Syntax

```c
void neat_start_event_loop(struct neat_ctx *ctx, neat_run_mode run_mode);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **run_mode**: The mode of which the event loop in NEAT should execute.
May be one of either `NEAT_RUN_DEFAULT`, `NEAT_RUN_ONCE`, or `NEAT_RUN_NOWAIT`.

### Return values

None.

### Remarks

This function does not return when executed with `NEAT_RUN_DEFAULT`.

When executed with `NEAT_RUN_ONCE`, NEAT will poll for I/O, and then
block _unless_ there are pending callbacks within NEAT that are ready to be
processed. These callbacks may be internal.

When executed with `NEAT_RUN_NOWAIT`, NEAT will poll for I/O and execute
any pending callbacks. If there are no pending callbacks, it returns after
polling.

### Examples

None.

### See also

- [neat_stop_event_loop](neat_stop_event_loop.md)
- [neat_get_backend_fd](neat_get_backend_fd.md)
