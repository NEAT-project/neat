## on_network_changed;

Inform application that something has happened in the
network. Includes flow endpoints going up (will also trigger
[`on_connected`](callb.on_connected) if that callback is set).

The nature of the network event is conveyed by the status code;
currently this is the SCTP state code, will be changed to a NEAT
abstracted code in a future iteration.

Conforms to the NETWORK_STATUS_CHANGE event in D1.2 section 3.2.3.

**Availability:** Currently only available when NEAT selects SCTP
  transport. The specification in D1.2 and
  draft-ietf-taps-transports-usage-00 for TCP relies on an API
  facility which does not exist; An alternative implementation
  mechanism is being investigated.
  
