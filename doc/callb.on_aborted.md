## on_aborted;

Inform application that the remote end has aborted the flow.

Conforms to the ABORT event in D1.2 section 3.2.4.

**Availability:** Currently only available when NEAT selects SCTP
  transport. The specification in D1.2 and
  draft-ietf-taps-transports-usage-00 does not specify this event for
  TCP; we are investigating how we might extend this work for TCP.
