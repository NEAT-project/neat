# NEAT examples
* [Basic client](#basic-client)
* [HTTP GET client](#http-get-client)
* [chargen/daytime/discard/echo servers](#chargendaytimediscardecho-servers)
* [tneat](#tneat)


## Basic client
The `client` reads data from `STDIN` and send it to the server. The received data is written to `STDOUT`.

```
client [OPTIONS] HOST PORT

-P : neat properties
-R : receive buffer in byte
-S : send buffer in byte
-v : log level (0 .. 2)
```

```
$ ./client -P "NEAT_PROPERTY_IPV6_REQUIRED,NEAT_PROPERTY_SCTP_REQUIRED" -v 2 www.neat-project.org 80
```


## HTTP GET client
`neat_http_get` sends a HTTP GET request on port 80 to a given `HOST` and writes the response to `STDOUT`.

By default the webservers root `/` is requested - an optional `URI` argument may be applied.

```
neat_http_get HOST [URI]
```

```
$ ./neat_http_get www.neat-project.org
```


## chargen/daytime/discard/echo servers
These servers are compatible with the `client` example and should show the basic functionality of the neat library.

* `server_chargen` - sends a sequence of ASCII characters until the peer disconnects.
* `server_daytime` - sends the current date and time to the peer and closes the connection
* `server_discard` - discards all received data
* `server_echo` - sends back an identical copy of the data it received

```
server_[chargen|daytime|discard|echo]

-P : neat property
-v : log level (0 .. 2)
-S : buffer in byte (discard and echo)
```


## tneat
`tneat` is a performance measurement tool.
When runnning as a server, tneat waits for incoming connections and prints statistics about when the connection finished.

As a client, tneat sends `-n <num>` messages with a size of `-l <byte>` bytes each to the `HOST` and closes the connection when finished.

```
tneat [OPTIONS] [HOST]

-l : message length in byte (client)
-n : number off messages to send (client)
-p : port
-P : neat properties
-R : receive buffer in byte (server)
-T : max runtime (client)
-v : log level (0 .. 2)
```

```
server:
$ ./tneat

client:
$ ./tneat localhost
```
