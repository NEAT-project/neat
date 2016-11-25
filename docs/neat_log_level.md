# neat_log_level
Set the log-level of the NEAT library.

### Syntax
```c
void neat_log_level(uint8_t level)
```

### Parameters
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
neat_log_level(NEAT_LOG_ERROR);
```

### See also

- [neat_log_file](neat_log_file.md)
