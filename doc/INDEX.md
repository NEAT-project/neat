# NEAT API

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
