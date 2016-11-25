# neat_get_backend_timeout

Return the timeout that should be used when polling the backend file descriptor.

### Syntax

```c
int neat_get_backend_timeout(struct neat_ctx *ctx);
```

### Parameters

- **ctx**: Pointer to a NEAT context.

### Return values

Returns the number of milliseconds on which a poll operation may at most be
blocked on the backend file descriptor from libuv before the NEAT event loop
should be executed again to take care of timer events within NEAT.

### Remarks

The `client_http_run_once` example demonstrates the use of this function.

### Examples

None.

### See also

- [neat_get_backend_fd](neat_get_backend_fd.md)
