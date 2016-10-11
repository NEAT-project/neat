# neat_read

Read data from a neat flow. Should only be called from within the `on_readable`
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
- **buffer**: Pointer to a buffer where read data may be stored.
- **amount**: The size of the buffer pointed to by **buffer**.
- **actual_amount**: The amount of data actually read from the transport layer.
- **optional**: An array containing optional parameters.
- **opt_count**: The length of the array containing optional parameters.

### Optional parameters

This function uses optional parameters for some return values.

- **NEAT_TAG_STREAM_ID** (integer): The ID of the stream will be written to this
parameter.

### Return values

- Returns `NEAT_OK` if data was successfully read from the transport layer.
- Returns `NEAT_ERROR_WOULD_BLOCK` if this call would block.
- Returns `NEAT_ERROR_MESSAGE_TOO_BIG` if the **buffer** is not sufficiently
  large. This is only returned for protocols that are message based, such as
  UDP, UDP-Lite and SCTP.
- Returns `NEAT_ERROR_IO` if the connection is reset.

### Remarks

This function should only be called from within the `on_readable` callback
specified with `neat_set_operations`, as this is the only way to guarantee
that the call will not block. NEAT does not permit a blocking read operation.

### Examples

None.

### See also

- [neat_write](neat_write.md)
- [Optional arguments](optargs.md)
