# neat_log_file
Sets the name of the log file.

### Syntax
```c
uint8_t neat_log_file(const char* file_name)
```

### Parameters
- **file_name**: Name of the NEAT logfile. If set to `NULL`, NEAT writes the log output to `stderr`.


### Return values
- **RETVAL_SUCCESS**: success
- **RETVAL_FAILURE**: failure

### Examples
```
neat_log_file("disaster.log");
```

### See also

- [neat_log_level](neat_log_level.md)
