## neat_request_capacity
```c
neat_error_code neat_request_capacity(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
	int rate, int seconds);
	```

Inform NEAT that the flow requires the specified rate for `seconds`
length of time after the request is made. This is only a hint, NEAT
provides no guarantees.

API conforms to REQUEST_CAPACITY in D1.2 section 3.3.2.

**Currently not implemented.**
