# NEAT API

## functions
#### neat_init_ctx()
```c
struct neat_ctx *neat_init_ctx();
```
Initialize neat context.

#### neat_start_event_loop()
```c
void neat_start_event_loop(
    struct neat_ctx *nc,
    neat_run_mode run_mode);
```
Start the internal NEAT event loop.

#### neat_stop_event_loop()
```c
void neat_stop_event_loop(
    struct neat_ctx *nc);
```
Stop the internal NEAT event loop.

#### neat_get_backend_fd()
```c
int neat_get_backend_fd(
    struct neat_ctx *nc);
```
Return the internal file descriptor.

####
```c
void neat_free_ctx(
    struct neat_ctx *nc);
```
Free any resource used by the context.
Loop must be stopped by `neat_stop_event_loop()` before this function is called.


#### neat_new_flow()
```c
struct neat_flow*
neat_new_flow(
    struct neat_ctx *ctx);
```
Create a new NEAT flow.

#### neat_free_flow()
```c
void neat_free_flow(
    struct neat_flow *flow);
```
Free the neat flow.

#### neat_set_operations()
```c
neat_error_code neat_set_operations(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    struct neat_flow_operations *ops);
```
Set the NEAT operation callbacks.

* on_connected
* on_error
* on_readable
* on_writable
* on_all_written

#### neat_open()
```c
neat_error_code neat_open(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    const char *name,
    const char *port);
```
Open a neat flow.

#### neat_read()
```c
neat_error_code neat_read(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    unsigned char *buffer,
    uint32_t amt,
    uint32_t *actualAmt);
```
Read data from a neat flow.

#### neat_write()
```c
neat_error_code neat_write(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    const unsigned char *buffer,
    uint32_t amt);
```
Write data to a neat flow.

#### neat_get_property()
```c
neat_error_code neat_get_property(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    uint64_t *outMask);
```
Get NEAT property mask.

#### neat_set_property
```c
neat_error_code neat_set_property(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    uint64_t inMask);
```
Set NEAT property mask.
See [Property](##Property) for details.

#### neat_accept
```c
neat_error_code neat_accept(
    struct neat_ctx *ctx,
    struct neat_flow *flow,
    const char *name,
    const char *port);
```
Accept a new flow.

#### neat_shutdown
```c
neat_error_code neat_shutdown(
    struct neat_ctx *ctx,
    struct neat_flow *flow);
```
Shutdown NEAT connection.

## Callbacks

### on_connected;
`neat_accept()` or `neat_open()` successfully established a connection

#### on_error;
Error occurred

### on_readable;
Data arrived and can be read by `neat_read()`

### on_writable;
Data can be sent via `neat_write()``

### on_all_written;
Data sent earlier via `neat_write()` has been processed and we can send more data via `neat_write()`

### Sample callback flow
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


## Properties
* NEAT_PROPERTY_OPTIONAL_SECURITY
* NEAT_PROPERTY_REQUIRED_SECURITY
* NEAT_PROPERTY_MESSAGE
* NEAT_PROPERTY_IPV4_REQUIRED          
* NEAT_PROPERTY_IPV4_BANNED               
* NEAT_PROPERTY_IPV6_REQUIRED               
* NEAT_PROPERTY_IPV6_BANNED                
* NEAT_PROPERTY_SCTP_REQUIRED               
* NEAT_PROPERTY_SCTP_BANNED                
* NEAT_PROPERTY_TCP_REQUIRED                
* NEAT_PROPERTY_TCP_BANNED               
* NEAT_PROPERTY_UDP_REQUIRED      
* NEAT_PROPERTY_UDP_BANNED          
* NEAT_PROPERTY_UDPLITE_REQUIRED         
* NEAT_PROPERTY_UDPLITE_BANNED         
* NEAT_PROPERTY_CONGESTION_CONTROL_REQUIRED
* NEAT_PROPERTY_CONGESTION_CONTROL_BANNED
* NEAT_PROPERTY_RETRANSMISSIONS_REQUIRED
* NEAT_PROPERTY_RETRANSMISSIONS_BANNED

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
