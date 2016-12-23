# neat_free_ctx

Summary.

### Syntax
```c
void neat_free_ctx(struct neat_ctx *ctx);
```

### Parameters

- **ctx**: Pointer to the NEAT context to free.

### Return values

None.

### Remarks

If there are any flows still kept in this context, those will be freed and
closed as part of this operation.

### Examples

None.

### See also

- [neat_close](neat_close)
- [neat_init_ctx](neat_init_ctx.md)
- [neat_new_flow](neat_new_flow.md)

