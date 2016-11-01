# neat_write

Write data to a neat flow. Should only be called from within the `on_writable`
callback specified with `neat_set_operations`.

```c
neat_error_code neat_read(struct neat_ctx *ctx,
                          struct neat_flow *flow,
                          unsigned char *buffer,
                          uint32_t amount,
                          uint32_t *actual_amount,
                          struct neat_tlv optional[],
                          unsigned int opt_count);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to a NEAT flow.
- **buffer**: Pointer to a buffer containing the data to be written.
- **amount**: The size of the buffer pointed to by **buffer**.
- **optional**: An array containing optional parameters.
- **opt_count**: The length of the array containing optional parameters.

### Optional parameters

- **NEAT_TAG_STREAM_ID** (integer): The ID of the stream the data will be written to.

### Return values

- Returns `NEAT_OK` if data was successfully written to the transport layer.
- Returns `NEAT_ERROR_BAD_ARGUMENT` if the specified stream ID is negative.
- Returns `NEAT_ERROR_OUT_OF_MEMORY` if NEAT is unable to allocate memory.
- Returns `NEAT_ERROR_WOULD_BLOCK` if this call would block.
- Returns `NEAT_ERROR_IO` if an I/O operation failed.

### Remarks

This function should only be called from within the `on_writable` callback
specified with `neat_set_operations`, as this is the only way to guarantee
that the call will not block. NEAT does not permit a blocking write operation.

Invalid stream IDs are silently ignored.

### Examples

None.

### See also

- [neat_read](neat_read.md)
- [Optional arguments](optargs.md)
