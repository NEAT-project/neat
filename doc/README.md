# NEAT documentation

* [Functions](#functions)
* [Callbacks](#callbacks)
* [Return codes](#return-codes)
* [Debug output](#debug-output)
* [Internals](#internals)
  * [DNS Resolver](#dns-resolver)   

## Functions
* [neat_init_ctx()](func.neat_init_ctx.md)
* [neat_start_event_loop()](func.neat_start_event_loop.md)
* [neat_stop_event_loop()](func.neat_stop_event_loop.md)
* [neat_get_backend_fd()](func.neat_get_backend_fd.md)
* [neat_free_ctx](func.neat_free_ctx.md)
* [neat_new_flow()](func.neat_new_flow.md)
* [neat_free_flow()](func.neat_free_flow.md)
* [neat_set_operations()](func.neat_set_operations.md)
* [neat_open()](func.neat_open.md)
* [neat_read()](func.neat_read.md)
* [neat_write()](func.neat_write.md)
* [neat_get_property()](func.neat_get_property.md)
* [neat_set_property()](func.neat_set_property.md)
* [neat_accept()](func.neat_accept.md)
* [neat_shutdown()](func.neat_shutdown.md)


## Callbacks
* [on_connected()](callb.on_connected.md)
* [on_error()](callb.on_error.md)
* [on_readable()](callb.on_readable.md)
* [on_writable()](callb.on_writable.md)
* [on_all_written()](callb.on_all_written.md)


#### Sample callback flow
```
                      +
                      |
                      |
                      |
             +--------v---------+
             |  on_connected()  |
             +--------+---------+
                      |
         +------------+-------------+
         |                          |
+--------v---------+       +--------v---------+
|   on_readable()  |       |   on_writable()  | <------+
+------------------+       +--------+---------+        |
                                    |                  |
                                    |                  |
                                    |                  |
                           +--------v---------+        |
                           | on_all_written() |  ------+
                           +------------------+
```

## Return codes

* NEAT_ERROR_OK
* NEAT_OK NEAT_ERROR_OK
* NEAT_ERROR_WOULD_BLOCK
* NEAT_ERROR_BAD_ARGUMENT
* NEAT_ERROR_IO
* NEAT_ERROR_DNS
* NEAT_ERROR_INTERNAL
* NEAT_ERROR_SECURITY
* NEAT_ERROR_UNABLE
* NEAT_ERROR_MESSAGE_TOO_BIG

## Debug output
Neat offers a flexible way to control debug output via environment variables.

| variable         | default           | supported values
| :-------------   |:------------------| :-------------
| `NEAT_LOG_LEVEL` | `NEAT_LOG_INFO`   | `NEAT_LOG_OFF`, `NEAT_LOG_ERROR`, `NEAT_LOG_WARNING`, `NEAT_LOG_INFO`, `NEAT_LOG_DEBUG`
| `NEAT_LOG_FILE`  | undefined (stderr)| filename, e.g. "neat.log"

## Internals
### DNS resolver

NEAT contains an asynchronous multi-prefix DNS resolver. DNS requests for the
given domain will be sent to four public DNS servers on every available
interface (address). It is possible to limit query to only v4 or v6 addresses,
and a v4 interface is only used to request A records while v6 is only used to
request AAAA records.

In case of DNS poisoning or similar, the resolved address is compared agains the
well-known internal IPs (ULA or IANA A/B/C). An internal IP is flagged and it is
(so far) up to the user of NEAT to know if it is safe or not to use this IP.

The best way to look at how to use the resolver is to look at the example file,
`neat_resolver_example.c`

### TODO
- [ ] Read DNS-servers from resolv.conf. This requires us to decide on a generic way
  for specifying with interface/IP a server belongs to.
- [ ] Make resolver work on other OS' than Linux.
- [ ] Make it optional (as much as possible) if resolver should use stack or heap.
- [ ] Design a better algorithm for choosing servers, prioritizing servers sent to
  user.
- [ ] Lots of other stuff that I can't think of now.

### TODO
- [ ] Give user control of how loop is run so that it for example can be integrated into other event loops.
- [ ] Monitor more stuff, like routes?
- [x] Implement some form of logging/verbose mode. This is something that we should all agree on.
- [ ] Find a platform-independent alternative to ldns.
