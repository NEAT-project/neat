# neat_shutdown

Initiate a graceful shutdown of this flow. All previously written data will be
sent. Data can still be read from the flow.

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
