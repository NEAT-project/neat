## on_send_failure;

`typedef void (*neat_cb_send_failure_t)(struct neat_flow_operations *flowops,
int context, const unsigned char *unsent);`

Inform the application that the returned message (in `unsent`) could
not be transmitted. The failure reason as reported by the transport
protocol is returned in the standard status code, as an abstracted
NEAT error code. If the message was tagged with a context number, it
is returned in `context`.

Conforms to the SEND_FAILURE event in D1.2 section 3.2.5.

**Availability:** As specified in D1.2 /
  draft-ietf-taps-transports-usage-00 this callback is only available
  when NEAT has selected SCTP transport. TCP does not provide any
  facility for detecting this beyond timeouts which abort the
  connection.
