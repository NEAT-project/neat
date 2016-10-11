# neat_secure_identity

Specify a certificate and key to use for secure connections.

### Syntax

```c
neat_error_code neat_secure_identity(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    const char *filename);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to a NEAT flow.
- **filename**: Path to the PEM file containing the certificate and key.

### Return values

- Returns `NEAT_OK`.

### Remarks

None.

### Examples

None.

### See also

None.
