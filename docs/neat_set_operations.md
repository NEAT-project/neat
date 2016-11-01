# neat_set_operations

Summary.

### Syntax

```c
neat_error_code neat_set_operations(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    struct neat_flow_operations *ops);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to a NEAT flow.
- **ops**: Pointer to a struct that defines the operations/callbacks for this
  flow.

### Return values

- Returns `NEAT_OK`.

### Remarks

`struct neat_flow_operations` is defined as follows:

```c
struct neat_flow_operations
{
    void *userData;

    neat_error_code status;
    int stream_id;
    neat_flow_operations_fx on_connected;
    neat_flow_operations_fx on_error;
    neat_flow_operations_fx on_readable;
    neat_flow_operations_fx on_writable;
    neat_flow_operations_fx on_all_written;
    neat_flow_operations_fx on_network_status_changed;
    neat_flow_operations_fx on_aborted;
    neat_flow_operations_fx on_timeout;
    neat_flow_operations_fx on_close;
    neat_cb_send_failure_t on_send_failure;
    neat_cb_flow_slowdown_t on_slowdown;
    neat_cb_flow_rate_hint_t on_rate_hint;

    struct neat_ctx *ctx;
    struct neat_flow *flow;
};
```

### Examples

```c
struct neat_flow_operations ops;
ops.on_readable = on_readable;
ops.on_writable = on_writable;
neat_set_operations(ctx, flow, ops);
```

### See also

None.
