#### neat_write()
```c
neat_error_code neat_write(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    const unsigned char *buffer,
    uint32_t amt);
```
Write data to a neat flow.
