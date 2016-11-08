# Callbacks

Callbacks are used in NEAT to signal events to the application. They are used
to inform the application when a flow is readable, writable, or an error has
occurred.

Most callbacks have the following syntax:

```c
neat_error_code
on_event_name(neat_flow_operations *ops)
{
    return NEAT_OK; // or some error code
}
```

The struct `neat_flow_operations` is defined as follows:

```c
struct neat_flow_operations
{
    void *userData;

    neat_error_code status;
    int stream_id;
    struct neat_ctx *ctx;
    struct neat_flow *flow;

    neat_flow_operations_fx on_connected;
    neat_flow_operations_fx on_error;
    neat_flow_operations_fx on_readable;
    neat_flow_operations_fx on_writable;
    neat_flow_operations_fx on_all_written;
    neat_flow_operations_fx on_network_status_changed;
    neat_flow_operations_fx on_aborted;
    neat_flow_operations_fx on_timeout;
    neat_flow_operations_fx on_close;
    neat_cb_send_failure_t on_send_failure;
    neat_cb_flow_slowdown_t on_slowdown;
    neat_cb_flow_rate_hint_t on_rate_hint;
};
```

- **userData**: Applications may freely store a pointer in this field.
- **status**: Reports any errors associated with the flow.
- **stream_id**: For flows that use explicit multistreaming. Specifies
which stream the event is related to, if any.
- **ctx**: Pointer to the context the flow belongs to.
- **flow**: Pointer to the flow on which the event happened.

Callbacks are set by assigning the function pointer to the struct passed to the
callback and then calling `neat_set_operations`. A `NULL` pointer may be used to
indicate that the callback should no longer be called.

## Example callback flow

For most applications it will be sufficient to use the following callback flow:

```
                      +
                      |
                      |
                      |
             +--------v---------+
             |  on_connected()  |
             +--------+---------+
                      |
         +------------+-------------+
         |                          |
+--------v---------+       +--------v---------+
|   on_readable()  |       |   on_writable()  | <------+
+------------------+       +--------+---------+        |
                                    |                  |
                                    |                  |
                                    |                  |
                           +--------v---------+        |
                           | on_all_written() |  ------+
                           +------------------+
```

See the [tutorial](tutorial.md) for more details.

## Callback reference

#### on_connected

Called whenever an outgoing connection has been established with `neat_open`,
or an incoming connection has been established with `neat_accept`.

#### on_error

Called whenever an error occurs when processing the flow. Errors are considered
critical.

#### on_readable

Called whenever the flow can be read from without blocking. NEAT does not permit
blocking reads.

#### on_writable

Called whenever the flow can be written to without blocking. NEAT does not
permit blocking writes.

#### on_all_written

Called when all previous data sent with `neat_write` has been completely
written. Does not signal that the flow is writable. Applications may use this
callback to re-enable the `on_writable` callback.

#### on_network_status_changed

Inform application that something has happened in the network. This also
includes flow endpoints going up, which will subsequently trigger
`on_connected` if that callback is set.

Only available when using SCTP.

#### on_aborted

Called when the remote end aborts the flow. Available for flows using TCP or SCTP.

#### on_timeout

Called if sent data is not acknowledged within the time specified with
`neat_change_timeout`.

Currently only available for TCP on Linux.

#### on_close

Called when the graceful connection shutdown has completed.

Only available when using SCTP or TCP. Note that when using TCP, this callback
is called when the `close()` system call is made, as TCP implementations currently
does not provide any more accurate way of signalling this.

#### on_send_failure

Defined as:
```c
void
on_send_failure(struct neat_flow_operations *flowops, int context, const unsigned char *unsent)
{
}
```

Called to inform the application that the returned message `unsent` could not be
transmitted. The failure reason as reported by the transport protocol is
returned in the standard status code, as an abstracted NEAT error code. If the
message was tagged with a context number, it is returned in context.

Only available for SCTP. Flows using TCP may use timeouts instead.

#### on_slowdown

Not currently implemented.

Defined as:
```c
void
on_slowdown(struct neat_flow_operations *ops, int ecn, uint32_t rate)
{
}
```

Inform the application that the flow has experienced congestion and that the
sending rate should be lowered. If `rate` is non-zero, it is an estimate of the
new maximum sending rate. `ecn` is a boolean indicating whether this
notification was triggered by an ECN mark.


#### on_rate_hint

Not currently implemented.

Defined as:
```c
void
on_rate_hint(struct neat_flow_operations *ops, uint32_t new_rate)
{
}
```

Called to inform the application that it may increase its sending rate. If
`new_rate` is non-zero, it is an estimate of the maximum sending rate.
