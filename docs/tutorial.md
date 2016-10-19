# Welcome to the NEAT tutorial

## What is NEAT?

NEAT is a library for networked applications, intended to replace
existing socket APIs with a simpler, more flexible API. Additionally, NEAT
enables endpoints to make better decisions as to how to utilize the available
network resources and adapts based on the current condition of the network.

With NEAT, applications are able to specify the service they want from the
transport layer. NEAT will determine which of the available protocols fit the
requirements of the application and tune all the relevant parameters to ensure
that the application gets the desired service from the transport layer, based
on knowledge about the current state of the network when this information is
available.

NEAT enables applications to be written in a protocol-agnostic way, thus
allowing applications to be future-proof, leveraging new protocols as they
become available, with minimal to no change. Further, NEAT will try to connect
with different protocols if possible, making it able to gracefully fall back to
another protocol if it turns out that the most optimal protocol is unavailable,
for example, because of a middlebox such as a firewall. A connection in the NEAT
API will only fail if all protocols satisfying the requirements of the
application are unable to connect, or if no available protocol can satisfy the
requirements of the application.

Most operating systems support the same protocols. However, the same protocol
may often have a slightly different API on different operating systems. NEAT
provides the same API on all supported operating systems, which is currently
Linux, FreeBSD, OpenBSD, NetBSD, and OS X. The availability of a protocol
depends on whether the protocol is supported by the OS or if NEAT is compiled
with support for a user-space stack that implements the protocol.

## Contexts and flows

<!--
- Context
    - A collection of flows,
    - At least one per application
- Flow
    - A bidirectional pipe for communication
    - Similar to a socket
-->

The most important concept in the NEAT API is that of the flow. A flow is
similar to a socket in the traditional Berkely Socket API. It is a
bidirectional link used to communicate between two applications, on which data
may be written to or read from. Further, just like a socket, a flow uses some
transport layer protocol to communicate.

However, one important difference is that a flow is not as strictly tied to the
underlying transport protocol in the same way a socket is. In fact, a flow may
be created without even specifying which transport protocol to use. This is not
possible with a socket.

The same applies to modifying options on sockets. Setting the same kind of
option on two sockets with different protocols in the traditional socket API
requires `setsockopt` calls with different protocol IDs, option names, and
sometimes even values with different units. The `setsockopt` calls also vary
depending on what system you are on. This is not the case with NEAT. As long as
the desired option is available for the protocol in use, the API for setting
that option is the same for all protocols, and on all operating systems
supported by NEAT.

A context is a common environment for multiple flows. Along with flows, it
contains several services that are used by the flows internally in NEAT, such
as a DNS resolver and a Happy Eyeballs implementation. Flows within a context
are polled together. A flow may only belong to the context in which it is
created, and it cannot be transferred to a different context. Most applications
need only one context.

## Properties

<!--
- Different applications have different requirements/desires
- BitTorrent, real-time communication
- A property describes the communication
- Requirements and desires
-->

Different types of applications have different requirements and desires to the
services provided by the transport layer. An application for real-time
communication may require the communication to have properties such as low
latency, high bandwidth, quality of service, and have less strict requirements
with regards to reliable delivery. Losing a packet or bit errors may be less
critical to these applications. A web browser, on the other hand, might require
communication that is (partially) ordered and error-free. A BitTorrent
application might only require the ability to send packets to some destination
with a minimum amount of effort, and not at the expense of other applications
with stricter bandwidth requirements.

With the traditional socket API, the application requirements dictate
the choice of which protocol to use. With NEAT, this is not the case. NEAT
enables applications to specify the properties of the communication instead of
specifying which protocol to use. Some properties may be required; other
properties may be desired, but not mandatory. Based on the properties, NEAT
will determine which protocols can support the requirements of the application
and the options to set for each protocol. It will try to establish a connection
by trying each of them until one connection succeeds, known as Happy
Eyeballing.

The ability to specify properties instead of protocols allows applications to
take advantage of available protocols where possible. By Happy Eyeballing, NEAT
ensures that applications are able to cope with different network
configurations, and gracefully fall back to another protocol if necessary
should the most desirable protocol not be available for whatever reason.

## Asynchronous API

The NEAT API is asynchronous and non-blocking. Once the execution is
transferred to NEAT, it will poll the sockets internally, and, when an event
happens, execute the appropriate callback in the application. This creates a
more natural way of programming communicating applications than with the
traditional socket API.

The three most important callbacks in the NEAT API are `on_connected`,
`on_readable` and `on_writable`, which may be set per flow. The `on_connected`
callback will be executed once the flow has connected to a remote endpoint, or
a flow has connected to a server listening for incoming connections. The
`on_writable` and `on_readable` callbacks are executed once data may be written
to or read from the flow without blocking.

## A minimal server

To get started using the NEAT API, we will write a small server that will send
`Hello, this is NEAT!` to any client that connects to it. Later, we will write a
similar client, before modifying this server so that it works with the client.

We can summarize the functionality as follows:

- When a client connects, start writing when the flow is writable
- When a flow is writable, write `Hello, this is NEAT!` to it.
- When the flow has finished writing, close it.

Pay close attention to how easily this natural description can be implemented
using the NEAT API.

Here are the includes that should be put on top of the file:

``` embed:: language::c
../examples/minimal_server.c:1-6
```

We will start writing the main function of our server. The first thing we need
to do is to declare a few variables:

``` embed:: language::c
../examples/minimal_server.c:44-48
```

And initialize them:

``` embed:: language::c
../examples/minimal_server.c:50-52
```

We are already familiar with the flow and the context. `neat_init_ctx` is used
to initialize the context, and `neat_new_flow` creates a new flow withing the
context. The `neat_flow_operations` struct is used to tell NEAT what to do
when certain events occur. We will use that next to tell which function we
want NEAT to call when a client connects:

``` embed:: language::c
../examples/minimal_server.c:55-56
```

The function `on_connected` has not been defined yet, we will do that later.
Now that we have told NEAT what to do with a connecting client, we are ready
to accept incoming connections.

``` embed:: language::c
../examples/minimal_server.c:58-61
```

This will instruct NEAT to start listening to incoming connections on port 5000.
The flow passed to `neat_accept` is cloned for each accepted connection. The
last two parameters are used for optional arguments. This example does not use
them.

The last function call we will do in main will be the one that starts the
show:

``` embed:: language::c
../examples/minimal_server.c:63-66
```

When this function is called, NEAT will start doing work behind the scenes.
When called with the `NEAT_RUN_DEFAULT` parameter, this function will not
return until all flows have closed and all events have been handled. It is
also possible to run NEAT without having NEAT capture the main loop. Our final
main function looks like this:

``` embed:: language::c
../examples/minimal_server.c:44-66
```

We have now filled in the main function of our server application. It is time
to start working on the callbacks that NEAT will use. The first callback we
need is `on_connected`.

``` embed:: language::c
../examples/minimal_server.c:33-35
```

From the functional description above, we know that we need to write to
connecting clients when this becomes possible. The callback contains a
parameter that is a pointer to a `neat_flow_operations` struct, which we can
use to update the active callbacks of the flow. We set the `on_writable`
callback so that we can start writing when the flow becomes writable:

``` embed:: language::c
../examples/minimal_server.c:36-36
```

It is also good practice to set the `on_all_written` callback when setting the
`on_writable` callback:

``` embed:: language::c
../examples/minimal_server.c:37-37
```

The change is applied by calling `neat_set_operations`, just as in the main function:

``` embed:: language::c
../examples/minimal_server.c:38-41
```

Next, we write the `on_writable` callback:

``` embed:: language::c
../examples/minimal_server.c:19-21
```

Here, we call the function that will send our message:

``` embed:: language::c
../examples/minimal_server.c:22-24
```

Here we specify the data to send and the length of the data.
As with the `neat_accept` function, `neat_write` takes optional parameters.
We do not need to set any optional parameters for this call either, so again we
pass `NULL` and `0`.

The final callback we need to implement is the `on_all_written` callback:

``` embed:: language::c
../examples/minimal_server.c:26-28
```

Here, we call `neat_close` to close the flow:

``` embed:: language::c
../examples/minimal_server.c:29-31
```

This is the final piece of our server. You may now compile and run the server.
You can use the tool `socat` to test it. The following output should be observed:

```
$ socat STDIO TCP:localhost:5000
Hello, this is NEAT!
$ socat STDIO SCTP:localhost:5000
Hello, this is NEAT!
```

You may find the complete source for the server [here](https://github.com/NEAT-project/neat/blob/oystedal/readthedocs/examples/minimal_server.c).

## A minimal client

Next, we want to implement a client that will send the message `"Hi!"` after
connecting to a server, and then receive a reply from the server. A fair amount
of the code will be similar to the server we wrote above, so you may make a
copy of the code for the server and use that as a starting point for the client.

We will make two additions and one change to the main function. First, since we
are connecting to a server, we change the `neat_accept` call to `neat_open` instead:

``` embed:: language::c
../examples/minimal_client.c:85-88
```

Next, we will specify a few properties for the flow:

``` embed:: language::c
../examples/minimal_client.c:56-67
```

These properties will tell NEAT that it can select either SCTP or TCP as the
transport protocol. The properties are applied with `neat_set_properties`, which
may be done at any point between `neat_new_flow` and `neat_open`.

Finally, we add `neat_free_ctx` after `neat_start_event_loop`, so that NEAT may
free any allocated resources and exit gracefully. The complete main function
of the client will look like this:

``` embed:: language::c
../examples/minimal_client.c:69-95
```

Leave the `on_connected` callback similar to the server.

We change the `on_writable` callback to send `"Hi!"` instead:

``` embed:: language::c
../examples/minimal_client.c:30-35
```

The `on_all_written` callback should not close the flow, but instead stop
writing and set the `on_readable` callback:

``` embed:: language::c
../examples/minimal_client.c:37-44
```

Finally, we will write an `on_readable` callback for the client. We allocate
some space on the stack to store the received data, and use a variable to store
the length of the received message. If the `neat_read` call returns successfully,
we print the message. Finally, we stop the internal event loop in NEAT, which
will eventually cause the call to `neat_start_event_loop` in the main function
to return. The `on_readable` callback should look like this:

``` embed:: language::c
../examples/minimal_client.c:13-28
```

And there we have our finished client! You can test it with `socat`:

```
$ socat TCP-LISTEN:5000 STDIO
```

When you run the client, you should see `Hi!` show up in the output from socat.
You can type a short message followed by pressing return, and it should show
up in the output on the client.

You may find the complete source for the client [here](https://github.com/NEAT-project/neat/blob/oystedal/readthedocs/examples/minimal_client.c).

## Tying the client and server together

A few small changes are required on the server to make the client and server
work together. In the `on_connected` callback, the server should set the
`on_readable` callback instead of the `on_writable` callback. An `on_readable`
callback should be added and read the incoming message from the client, and set
the `on_writable` callback.

The callbacks for the updated server is as follows:

``` embed:: language::c
../examples/minimal_server2.c:16-68
```

You may find the complete source for the updated server [here](https://github.com/NEAT-project/neat/blob/oystedal/readthedocs/examples/minimal_server2.c).
