# Architecture

<object type="image/svg+xml" data="_static/neat.svg">
    Your browser does not support SVG
</object>

## Application

The application in NEAT terminology is the software using the transport layer to
communicate with a remote endpoint.

## NEAT API

The NEAT API is the public interface which applications may use to implement
communication over the transport layer.

## NEAT Core

The NEAT Core ties all the various components of the NEAT framework together,
and handles communication over the transport layer once the connection has been
established.

<!--
## Policy Manager
## Happy Eyeballs
## Name Resolver -->

## Connection setup in NEAT

The following is a description of how a connection is set up in NEAT:

1. The application specifies properties of the communication with `neat_set_property`.
2. The application calls `neat_open` in the NEAT API.
3. The NEAT Core sends application properties and inferred properties to the Policy Manager.
4. The Policy Manager replies with an initial set of candidates eligible for name resolution (e.g. DNS lookup).
5. The NEAT Core initiates one or more name resolution requests to the Name Resolver.
6. The Name Resolver replies with resolved addresses, and the NEAT Core inserts these into each candidate.
7. The NEAT Core makes a second call to the Policy Manager.
8. The Policy Manager returns a list of suitable candidates that the NEAT Core should use to establish a connection.
   A candidate consists of the following:
   - Transport protocol
   - Interface
   - Port
   - Local address
   - Remote address
   - Priority
   - Application properties

   If one or more of the application properties are specified as desired (precedence 1), multiple
   candidates *may* be generated with different settings for that property.
9. The NEAT Core generates a list of Happy Eyeball candidates and initiates the Happy Eyeballs algorithm.
10. The Happy Eyeballs module tries to connect each candidate in turn.
    The delay between each candidate is determined from the priority of the candidate.
    A lower value implies a higher priority.
    The connection may be handled by either the operating system using its own
    implementation of the protocol, or using a userspace implementation of the protocol.
11. The first connection that connects successfully and meets all required properties
    set by the application is returned to the NEAT Core.
12. NEAT starts polling the socket internally, and reports back to the application
    that a connection has been established using the `on_connected` callback if
    it has been specified using `neat_set_operations`.
13. NEAT will report that the flow is readable or writable if the respective `on_readable`
    or `on_writable` callbacks have been specified with `neat_set_operations`.
14. The application closes the flow with `neat_close`.

