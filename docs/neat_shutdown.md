# neat_shutdown

Initiate a graceful shutdown of this flow.

* the receive buffer can still be read and `on_readable` gets fired like in normal operation
* receiving **new** data from the peer **may** fail
* all data in the *send buffer* will be transmitted
* `neat_write` will fail and `on_writable` will not be called

If the peer also has closed the connection, the `on_close` callback gets fired.

### Syntax

```c
neat_error_code neat_shutdown(struct neat_ctx *ctx,
                              struct neat_flow *flow);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to the NEAT flow to be shut down.

### Return values

- Returns `NEAT_OK` if the flow was shut down successfully.
- Returns `NEAT_ERROR_IO` if NEAT was unable to shut the flow down successfully.

### Remarks

None.

### Examples

None.

### See also

- [neat_close](neat_close.md)
