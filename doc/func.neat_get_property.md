## neat_get_property()
```c
neat_error_code neat_get_property(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    uint64_t *outMask);
```
Get NEAT property mask.

### Example
```c
neat_get_property(ctx, flow, &prop);
prop |= NEAT_PROPERTY_OPTIONAL_SECURITY;
prop |= NEAT_PROPERTY_TCP_REQUIRED; /* FIXME: Remove this once HE works */
neat_set_property(ctx, flow, prop);
```
