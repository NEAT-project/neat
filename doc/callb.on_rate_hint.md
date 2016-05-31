## on_rate_hint;

`typedef void (*neat_cb_flow_rate_hint_t)(struct neat_flow_operations
*ops, uint32_t new_rate);`

Inform the application that the flow can increase its sending rate. If
`new_rate` is non-zero, it is an estimate of the new maximum sending
rate.

Conforms to the RATE_HINT event in D1.2 section 3.3.3.

**Availability:** Not currently triggered.
