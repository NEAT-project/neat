# neat_get_stats

Return statistics from a NEAT context.

### Syntax

```c
neat_error_code neat_get_stats(
    struct neat_ctx *ctx,
    char **json_stats);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **json_stats**: Pointer to an address where address of the statistics may be
  written.

### Return values

- Returns `NEAT_OK`.

### Remarks

The statistics is output in JSON format. The caller is responsible for freeing
the buffer containing the statistics.

### Examples

None.

### See also

None.
