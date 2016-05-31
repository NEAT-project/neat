## neat_set_primary_dest
```c
neat_error_code neat_set_primary_dest(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
	const char *name);
	```

Set which address should be considered primary address for flows
with multiple destination addresses.

Conforms to SET_PRIMARY in D1.2 section 3.2.3.
