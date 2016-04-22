## neat_set_operations()
```c
neat_error_code neat_set_operations(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    struct neat_flow_operations *ops);
```
Set the NEAT operation callbacks.

* on_connected
* on_error
* on_readable
* on_writable
* on_all_written
