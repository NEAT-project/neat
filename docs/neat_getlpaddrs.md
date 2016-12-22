# neat_getlpaddrs

Obtains the local or peer addresses of a flow.

### Syntax

```c
int neat_getlpaddrs(struct neat_ctx*  ctx,
                    struct neat_flow* flow,
                    struct sockaddr** addrs,
                    const int         local)
```

### Parameters

- **ctx**: Pointer to a NEAT context.
- **flow**: Pointer to a NEAT flow.
- **addrs**: Pointer to variable for storing pointer to addresses to.
- **local**: Set to non-zero value for obtaining local addresses, set to 0 to obtain peer addresses.

### Return values

On success, neat_getlpaddrs() returns the number of addresses (local or remote). In case of having more than 1 address, a pointer to a newly allocated memory area with the addresses will be stored into addrs. This memory area needs to be freed after usage.

### Examples

struct struct sockaddr* addrs;
int n;
if((n = neat_getlpaddrs(ctx, flow, &addrs, 1)) > 0) {
   /* Do something with the addresses */
   free(addrs);
}
