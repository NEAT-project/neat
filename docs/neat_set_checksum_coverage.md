# neat_set_checksum_coverage

Set the checksum coverage for messages sent or received on this flow.

### Syntax

```c
neat_error_code neat_set_checksum_coverage(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    unsigned int send_coverage,
    unsigned int receive_coverage);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to a NEAT flow.
- **send_coverage**: UDP-Lite: The number of bytes covered by the checksum when sending messages. UDP: Ignored.
- **receive_coverage**: UDP-Lite: The lowest number of bytes that must be covered by the checksum on a received message. UDP: See below.

### Return values

- Returns `NEAT_OK` if the checksum coverage was set successfully.
- Returns `NEAT_ERROR_UNABLE` if the checksum coverage cannot be set, either
  because the value is invalid, or because the protocol does not support it.

### Remarks

Only available for flows using UDP or UDP-Lite.

Checksum verification may be enabled disabled on the receive side for flows using UDP.
Specifying a non-zero value for **receive_coverage** will enable it; specifying `0` will disable it.

### Examples

None.

### See also

None.
