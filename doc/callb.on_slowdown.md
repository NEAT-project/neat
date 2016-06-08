## on_slowdown;

`typedef void (*neat_cb_flow_slowdown_t)(struct neat_flow_operations
*ops, int ecn, uint32_t rate);`

Inform the application that the flow has experienced congestion and
that the sending rate should be lowered. If `rate` is non-zero, it is
an estimate of the new maximum sending rate. `ecn` is a boolean
indicating whether this notification was triggered by an ECN mark.

Conforms to the SLOWDOWN event in D1.2 section 3.3.3.

**Availability:** Not currently triggered.
