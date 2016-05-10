# NEAT samples


## client
The client reads data from STDIN and send it to the server. The received data is written to STDOUT.

```
client [OPTIONS] HOST PORT

-P : neat properties
-R : receive buffer in byte
-S : send buffer in byte
-v : log level (0 .. 2)
```

```
client www.neat-project.org 80 -P "NEAT_PROPERTY_IPV6_REQUIRED,NEAT_PROPERTY_SCTP_REQUIRED" -v 2
```

## tneat
Tneat is a performance measurement tool.
When runnning as a server, tneat waits for incoming connections and prints statistics about when the connection finished.

As a client, tneat sends `-n <num>` messages with a size of `-l <byte>` bytes each to the `[HOST]` and closes the connection when finished. 

```
tneat [OPTIONS] [HOST]

-l : message length in byte (client)
-n : number off messages to send (client)
-p : port
-P : neat properties
-R : receive buffer in byte (server)
-T : max runtime (client)
-v : log level
```
