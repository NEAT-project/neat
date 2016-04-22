## neat_read()
```c
neat_error_code neat_read(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    unsigned char *buffer,
    uint32_t amt,
    uint32_t *actualAmt);
```
Read data from a neat flow.
