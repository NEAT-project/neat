# neat_change_timeout

Change the timeout of the flow. Data that is sent may remain un-acked for up
to a given number of seconds before the connection is terminated and a timeout
is reported to the application.

### Syntax

```c
neat_error_code
neat_change_timeout(struct neat_ctx *ctx, struct neat_flow *flow,
                    unsigned int seconds);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to a NEAT flow.
- **seconds**: The number of seconds after which un-acked data will cause a
  timeout to be reported.

### Return values

- Returns `NEAT_OK` if the timeout was successfully changed.
- Returns `NEAT_ERROR_UNABLE` if attempting to use this function on a system
  other than Linux, or on flow that is not using TCP.
- Returns `NEAT_ERROR_BAD_ARGUMENT` if the timeout value is too large or if
  the specified flow is not opened.
- Returns `NEAT_ERROR_IO` if NEAT was unable to set the timeout.

### Remarks

Only available on Linux for flows using TCP.

### Examples

None.

### See also

None.
