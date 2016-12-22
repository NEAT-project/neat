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

On success, neat_getlpaddrs() returns the number of addresses (local or remote). In case of having obtained at least one address, a pointer to a newly allocated memory area with the addresses will be stored into addrs. This memory area needs to be freed after usage.

### Examples

```c
struct struct sockaddr* addrs;
int n = neat_getlpaddrs(ctx, flow, &addrs, 1);
if(n > 0) {
   struct sockaddr* a = addrs;
   for(int i = 0; i < n; i++) {
      switch(a->sa_family) {
         case AF_INET:
            printf("Address %d/%d: IPv4\n", i, n);
            a = (struct sockaddr*)((long)a + (long)sizeof(sockaddr_in));
          break;
         case AF_INET6:
            printf("Address %d/%d: IPv6\n", i, n);
            a = (struct sockaddr*)((long)a + (long)sizeof(sockaddr_in6));
         default:
            assert(false);
          break;
      }
   }
   free(addrs);
}
```
