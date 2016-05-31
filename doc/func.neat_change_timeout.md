## neat_change_timeout
```c
neat_error_code neat_change_timeout(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
	int seconds);
	```

Change the length of time NEAT will wait for data to be delivered
succesfully.  In case of a timeout, NEAT terminates the flow.

API conforms to CHANGE_TIMEOUT in D1.2 section 3.2.3.

**Limited implementation**: currently only implemented for TCP, relies
on the TCP User Timeout extension.
