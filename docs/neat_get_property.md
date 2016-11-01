# neat_get_property

Query the properties of a flow. Returns value only, not precedence.

### Syntax

```c
neat_error_code neat_get_property(struct neat_ctx *ctx,
                                  struct neat_flow *flow,
                                  const char *name,
                                  void *ptr,
                                  size_t *size);
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to a NEAT flow.
- **name**: Name of the property to query.
- **ptr**: Pointer to a buffer where the property value may be stored.
- **size**: Pointer to an integer containing the size of the buffer pointed to
  by `ptr`. Updated to contain the size of the property upon return.

### Return values

- Returns `NEAT_OK` if the property existed and there was sufficient buffer
  space available. The `size` parameter is updated to contain the actual size.
- Returns `NEAT_ERROR_MESSAGE_TOO_BIG` if there was not sufficient buffer
  space. The `size` parameter is updated to contain the required buffer size.
- Returns `NEAT_ERROR_UNABLE` if the property does not exist.

### Remarks

Applications may pass `0` as the `size` parameter to query the size of the
property.

### Examples

```c
    size_t bufsize = 0;
    char buffer = NULL;

    if (neat_get_property(ctx, flow, "transport", buffer, &bufsize) == NEAT_ERROR_MESSAGE_TOO_BIG) {
        buffer = malloc(bufsize);
        if (buffer && neat_get_property(ctx, flow, "transport", buffer, &bufsize) == NEAT_OK) {
            printf("Transport: %s\n", buffer);
        }
        if (buffer)
            free(buffer);
    } else {
        printf("\tTransport: Error: Could not find property \"transport\"\n");
    }
```

### See also

- [Properties](properties.md)
- [neat_set_property](neat_set_property.md)
