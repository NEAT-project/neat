# neat_log_level
Set the log-level of the NEAT library.

### Syntax
```c
void neat_log_level(struct neat_ctx *ctx,
                    uint8_t level)
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **level**: Log level of the log entry
    - NEAT_LOG_OFF
    - NEAT_LOG_ERROR
    - NEAT_LOG_WARNING
    - NEAT_LOG_ERROR
    - NEAT_LOG_DEBUG

### Return values
None.

### Examples
```
neat_log_level(ctx, NEAT_LOG_ERROR);
```

### See also

- [neat_log_file](neat_log_file.md)
