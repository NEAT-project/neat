## neat_close
```c
neat_error_code neat_close(
    struct neat_ctx *ctx,
    struct neat_flow *flow);
```
Gracefully close NEAT connection, allowing all buffered data to be
transmitted.

Conforms to CLOSE in D1.2 section 3.2.4.
