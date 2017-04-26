# neat_close

Close this flow and free all associated data.

This is the *last call*:
* all flow related data (e.g. `userData`) should be freed in advance
* no flow related *callbacks* are fired
* all data in the *receive buffer* gets discarded
* all data in the *send buffer* will be transmitted
* initiates a *graceful connection shutdown*

**This function must always the be called to free ressources**

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
