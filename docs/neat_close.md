# neat_close
Close this flow and free all associated data. If the peer still has data to send, it cannot be received anymore after this call. Data buffered by the NEAT layer which has not given to the network layer yet will be discarded.

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
