## on_close;

The graceful connection shutdown process has completed.

Conforms to the CLOSE event in D1.2 section 3.2.4.

**Availability:** As specified in D1.2 /
  draft-ietf-taps-transports-usage-00 this callback is only available
  when NEAT has selected SCTP transport. As an extension, we also call
  it when TCP has been selected. In that case, it is called right
  after the `close()` system call is made -- the TCP API does not
  provide a more accurate notification.
