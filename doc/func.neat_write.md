## neat_write()
```c
neat_error_code neat_write(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    const unsigned char *buffer,
    uint32_t amt);
```
Write data to a neat flow.

## neat_write_ex()
```c
neat_error_code neat_write(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    const unsigned char *buffer,
    uint32_t amt,
	int stream_id, int context, int pr_method, int pr_value,
    const char* preferred_destination, int unordered,
    float priority);
```
Write data to a neat flow, with multi-streaming parameters. Conforms
to API interface defined in D1.2 section 3.2.5.

**Currently unimplemented**
