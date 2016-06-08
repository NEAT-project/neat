## neat_open()
```c
neat_error_code neat_open(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    const char *name,
    uint16_t port);
```
Open a neat flow.

## neat_open_localname()
```c
neat_error_code neat_open(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    const char *name,
    uint16_t port,
    const char *localname);
```
Open a neat flow, explicitly specifying which local address to use.

**Currently not implemented:** if `localname` is NULL, behaviour is
  identical to `neat_open`; otherwise the call currently fails.

## neat_open_multistream()
```c
neat_error_code neat_open(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    const char *name,
    uint16_t port,
    const char *localname,
	int cout);
	```
	
Open a neat flow, explicitly specifying which local address to use as
well as the number of subflows to open. If it is not possible to open
the requested number of subflows for whatever reason (e.g. if no
transport protocols capable of multi-streaming are available), the
call fails.

API conformant to OPEN in D1.2 section 3.2.1.

**Currently not implemented:** if `localname` is NULL and `count`
  equals 1, behaviour is identical to `neat_open`; otherwise the call
  currently fails.
