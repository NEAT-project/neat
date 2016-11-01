# Error codes

#### NEAT_OK

Signals that no error has occurred. Equals to `0`.

#### NEAT_ERROR_WOULD_BLOCK

Signals that the operation could not be performed because it would block the
process. NEAT does not permit blocking operations.

#### NEAT_ERROR_BAD_ARGUMENT

Signals that one or more arguments given to the function was invalid or incorrect.
This also includes optional arguments.

#### NEAT_ERROR_IO

Signals that an internal I/O operation in NEAT has failed.

#### NEAT_ERROR_DNS

Signals that there was an error performing DNS resolution.

#### NEAT_ERROR_INTERNAL

Signals that there was an error internally in NEAT.

#### NEAT_ERROR_SECURITY

Signals that there was an error setting up an encrypted flow.

#### NEAT_ERROR_UNABLE

Signals that NEAT is not able to perform the requested operation.

#### NEAT_ERROR_MESSAGE_TOO_BIG

Signals that the provided buffer space is not sufficient for the received message.

#### NEAT_ERROR_REMOTE

Signals that there was an error on the remote endpoint.

#### NEAT_ERROR_OUT_OF_MEMORY

Signals that NEAT is not able to allocate enough memory to complete the requested
operation.

