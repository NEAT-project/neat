## neat_abort
```c
neat_error_code neat_abort(
    struct neat_ctx *ctx,
    struct neat_flow *flow);
	```
	
Abortively close NEAT connection. Buffered data is immediately
discarded, if possible the remote host is notified of the connection
abortion.

Conforms to ABORT in D1.2 section 3.2.4.
